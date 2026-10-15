//! Proc macros for `marmot-uniffi`.
//!
//! [`macro@on_tokio_runtime`] makes every `async fn` that a `#[uniffi::export]`
//! impl block exports run on the MarmotKit Tokio runtime, so a host thread only
//! ever polls a join handle.

use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::{format_ident, quote};
use syn::ext::IdentExt;
use syn::spanned::Spanned;
use syn::{
    Attribute, FnArg, Ident, ImplItem, ImplItemFn, ItemImpl, LitStr, Meta, Pat, Visibility,
    parse_macro_input, parse_quote,
};

/// Export each `async fn` of an impl block through a wrapper that runs it on
/// the MarmotKit Tokio runtime.
///
/// Place it directly above `#[uniffi::export]` on an inherent impl. For every
/// `pub async fn name(&self, args..) -> T`, the expansion:
///
/// - keeps `name` exactly as written, in a separate impl block that UniFFI
///   does not export, so Rust callers (other exports, `marmot-c`, tests) still
///   run it inline on their own runtime;
/// - exports a rustdoc-hidden `pub async fn __ffi_name(self: &Arc<Self>,
///   args..) -> T` in its place, under the FFI name `name` and with the same
///   docs and UniFFI defaults. It clones the `Arc` and awaits
///   `crate::tokio_runtime::spawn_export(..)` on `name`.
///
/// Two method markers change the wrapper: [`macro@receive`] polls the method on
/// the caller's thread instead of spawning it, and
/// [`macro@survives_cancellation`] keeps its task running when the call is
/// dropped.
///
/// The generated bindings, symbol names and checksums are unchanged: UniFFI
/// derives them from the exported name, and receiver kind is not part of its
/// metadata. Synchronous methods and constructors are exported as written.
/// The export must not carry `async_runtime`: that would wrap the join handle
/// in `async_compat` and bring back its fallback runtime thread.
#[proc_macro_attribute]
pub fn on_tokio_runtime(args: TokenStream, input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as ItemImpl);
    if !args.is_empty() {
        return syn::Error::new(Span::call_site(), "on_tokio_runtime takes no arguments")
            .to_compile_error()
            .into();
    }
    expand(item)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// Mark an async export, inside an [`macro@on_tokio_runtime`] block, that
/// hands the host the next item from a channel or watch.
///
/// Its wrapper polls it on the calling thread with MarmotKit's runtime entered
/// instead of spawning it, so the body advances only while the host polls and
/// a cancelled call never consumes an item. Keep such bodies to waiting and
/// converting; the work that produces items already runs on the runtime.
#[proc_macro_attribute]
pub fn receive(_args: TokenStream, _input: TokenStream) -> TokenStream {
    marker_outside_block("receive")
}

/// Mark an async export, inside an [`macro@on_tokio_runtime`] block, whose
/// work must finish even when the host cancels the call, such as terminal
/// shutdown.
///
/// Its wrapper spawns it like any other export but leaves the task running
/// when the call is dropped, so the work starts even if the host gives up
/// before a runtime worker first polls it.
#[proc_macro_attribute]
pub fn survives_cancellation(_args: TokenStream, _input: TokenStream) -> TokenStream {
    marker_outside_block("survives_cancellation")
}

/// The block macro strips both markers, so expanding one means it is misplaced.
fn marker_outside_block(marker: &str) -> TokenStream {
    syn::Error::new(
        Span::call_site(),
        format!("#[{marker}] only applies to an async method inside an #[on_tokio_runtime] impl"),
    )
    .to_compile_error()
    .into()
}

/// How an export's wrapper runs the original method.
#[derive(Clone, Copy)]
enum Mode {
    /// Spawned on the runtime; dropping the call aborts the task.
    Spawned,
    /// Polled on the caller's thread with the runtime entered.
    Receive,
    /// Spawned on the runtime; dropping the call leaves the task running.
    SurvivesCancellation,
}

/// Remove the mode markers from `attrs` and return the mode they select.
fn take_mode(attrs: &mut Vec<Attribute>) -> syn::Result<Mode> {
    let mut markers = Vec::new();
    attrs.retain(|attr| {
        let mode = if is_marker(attr, "receive") {
            Mode::Receive
        } else if is_marker(attr, "survives_cancellation") {
            Mode::SurvivesCancellation
        } else {
            return true;
        };
        markers.push((mode, attr.span()));
        false
    });
    match markers.as_slice() {
        [] => Ok(Mode::Spawned),
        [(mode, _)] => Ok(*mode),
        [_, (_, span), ..] => Err(syn::Error::new(
            *span,
            "an export takes at most one of #[receive] and #[survives_cancellation]",
        )),
    }
}

fn is_marker(attr: &Attribute, name: &str) -> bool {
    let segments: Vec<_> = attr.path().segments.iter().map(|s| &s.ident).collect();
    match segments.as_slice() {
        [marker] => *marker == name,
        [krate, marker] => *krate == "marmot_uniffi_macros" && *marker == name,
        _ => false,
    }
}

fn expand(mut exported: ItemImpl) -> syn::Result<proc_macro2::TokenStream> {
    check_export_attribute(&exported)?;
    if let Some((_, path, _)) = &exported.trait_ {
        return Err(syn::Error::new(
            path.span(),
            "on_tokio_runtime applies to inherent impls only",
        ));
    }
    if !exported.generics.params.is_empty() {
        return Err(syn::Error::new(
            exported.generics.span(),
            "on_tokio_runtime does not support generic impls",
        ));
    }

    let mut originals = Vec::new();
    for item in &mut exported.items {
        if let ImplItem::Fn(method) = item
            && method.sig.asyncness.is_some()
        {
            let mode = take_mode(&mut method.attrs)?;
            let wrapper = ffi_wrapper(method, mode)?;
            let mut original = std::mem::replace(method, wrapper);
            original.attrs.retain(|attr| !is_uniffi(attr));
            originals.push(original);
        }
    }

    let self_ty = &exported.self_ty;
    Ok(quote! {
        #exported

        impl #self_ty {
            #(#originals)*
        }
    })
}

/// Require `#[uniffi::export]` below this attribute, without `async_runtime`.
fn check_export_attribute(item: &ItemImpl) -> syn::Result<()> {
    let Some(export) = item
        .attrs
        .iter()
        .find(|attr| is_uniffi_path(attr, "export"))
    else {
        return Err(syn::Error::new(
            Span::call_site(),
            "place on_tokio_runtime directly above #[uniffi::export]",
        ));
    };
    if quote!(#export).to_string().contains("async_runtime") {
        return Err(syn::Error::new(
            export.span(),
            "remove async_runtime: on_tokio_runtime already runs async exports on Tokio",
        ));
    }
    Ok(())
}

/// The exported `__ffi_` wrapper for `method`.
fn ffi_wrapper(method: &ImplItemFn, mode: Mode) -> syn::Result<ImplItemFn> {
    match method.sig.inputs.first() {
        Some(FnArg::Receiver(receiver))
            if receiver.reference.is_some() && receiver.mutability.is_none() => {}
        _ => {
            return Err(syn::Error::new(
                method.sig.span(),
                "on_tokio_runtime async exports must take `&self`",
            ));
        }
    }

    let name = &method.sig.ident;
    let mut wrapper = method.clone();
    wrapper.sig.ident = format_ident!("__ffi_{}", name.unraw());
    wrapper.vis = Visibility::Public(Default::default());
    wrapper.sig.inputs[0] = parse_quote!(self: &::std::sync::Arc<Self>);

    let mut arg_names = Vec::new();
    for arg in wrapper.sig.inputs.iter_mut().skip(1) {
        let FnArg::Typed(typed) = arg else {
            unreachable!("only the first input can be a receiver");
        };
        let Pat::Ident(pat) = typed.pat.as_mut() else {
            return Err(syn::Error::new(
                typed.pat.span(),
                "on_tokio_runtime async exports need plain argument names",
            ));
        };
        // The wrapper forwards arguments unchanged, so it never needs `mut`.
        pat.mutability = None;
        arg_names.push(pat.ident.clone());
    }
    for arg in method.sig.inputs.iter().skip(1) {
        if let FnArg::Typed(typed) = arg
            && let Some(attr) = typed.attrs.first()
        {
            return Err(syn::Error::new(
                attr.span(),
                "on_tokio_runtime does not forward argument attributes",
            ));
        }
    }

    wrapper.attrs = exported_attrs(&method.attrs, name)?;
    let this = Ident::new("this", Span::mixed_site());
    wrapper.block = match mode {
        Mode::Spawned => parse_quote!({
            let #this = ::std::sync::Arc::clone(self);
            crate::tokio_runtime::spawn_export(async move { #this.#name(#(#arg_names),*).await })
                .await
        }),
        Mode::SurvivesCancellation => parse_quote!({
            let #this = ::std::sync::Arc::clone(self);
            crate::tokio_runtime::spawn_detached_export(async move {
                #this.#name(#(#arg_names),*).await
            })
            .await
        }),
        Mode::Receive => parse_quote!({
            crate::tokio_runtime::poll_on_caller(self.#name(#(#arg_names),*)).await
        }),
    };
    Ok(wrapper)
}

/// The wrapper's attributes: the original's, hidden from Rust docs, with
/// `name` merged into its `#[uniffi::method]` so the FFI name is unchanged.
fn exported_attrs(attrs: &[Attribute], name: &Ident) -> syn::Result<Vec<Attribute>> {
    let ffi_name = LitStr::new(&name.unraw().to_string(), name.span());
    // UniFFI reads every `doc` attribute as a docstring and rejects
    // `#[doc(hidden)]`; behind `cfg_attr` it only reaches rustdoc.
    let mut exported = vec![parse_quote!(#[cfg_attr(doc, doc(hidden))])];
    let mut renamed = false;
    for attr in attrs {
        if !is_uniffi_path(attr, "method") {
            exported.push(attr.clone());
            continue;
        }
        let args = match &attr.meta {
            Meta::Path(_) => quote!(),
            Meta::List(list) => {
                if list.tokens.clone().into_iter().any(|token| {
                    matches!(token, proc_macro2::TokenTree::Ident(ident) if ident == "name")
                }) {
                    return Err(syn::Error::new(
                        attr.span(),
                        "on_tokio_runtime sets the FFI name; rename the method instead",
                    ));
                }
                let tokens = &list.tokens;
                quote!(, #tokens)
            }
            Meta::NameValue(_) => {
                return Err(syn::Error::new(
                    attr.span(),
                    "unsupported uniffi::method form",
                ));
            }
        };
        exported.push(parse_quote!(#[uniffi::method(name = #ffi_name #args)]));
        renamed = true;
    }
    if !renamed {
        exported.push(parse_quote!(#[uniffi::method(name = #ffi_name)]));
    }
    Ok(exported)
}

fn is_uniffi_path(attr: &Attribute, last: &str) -> bool {
    let segments: Vec<_> = attr.path().segments.iter().map(|s| &s.ident).collect();
    segments.len() == 2 && segments[0] == "uniffi" && segments[1] == last
}

fn is_uniffi(attr: &Attribute) -> bool {
    attr.path()
        .segments
        .first()
        .is_some_and(|segment| segment.ident == "uniffi")
}
