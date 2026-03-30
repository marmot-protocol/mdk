/// Generates fluent builder-pattern setter methods in batch.
///
/// Each entry produces a `pub fn name(mut self, ...) -> Self` method.
/// Default behavior wraps the value in `Some()`. Use `<direct>` to skip wrapping.
///
/// # Syntax
///
/// ```ignore
/// setters! {
///     /// doc comment
///     name: Type;                               // self.name = Some(name)
///     name: impl Into<Type>;                    // self.name = Some(name.into())
///     name<direct>: Type;                       // self.name = name
///     method -> field: Type;                    // self.field = Some(field)
///     method<direct> -> field: Type;            // self.field = field
///     method -> field: impl Into<Type>;         // self.field = Some(field.into())
///     method<direct> -> field: impl Into<Type>; // self.field = field.into()
/// }
/// ```
#[macro_export]
macro_rules! setters {
    // === impl Into<T> arms (must come before $ty:ty arms) ===

    // impl Into + <direct> + rename
    (
        $(#[$meta:meta])*
        $method:ident < direct > -> $field:ident : impl Into< $inner:ty >;
        $($rest:tt)*
    ) => {
        $(#[$meta])*
        pub fn $method<T>(mut self, $field: T) -> Self
        where
            T: Into<$inner>,
        {
            self.$field = $field.into();
            self
        }
        $crate::setters!($($rest)*);
    };

    // impl Into + rename (default = Some)
    (
        $(#[$meta:meta])*
        $method:ident -> $field:ident : impl Into< $inner:ty >;
        $($rest:tt)*
    ) => {
        $(#[$meta])*
        pub fn $method<T>(mut self, $field: T) -> Self
        where
            T: Into<$inner>,
        {
            self.$field = Some($field.into());
            self
        }
        $crate::setters!($($rest)*);
    };

    // impl Into + <direct> + no rename
    (
        $(#[$meta:meta])*
        $name:ident < direct > : impl Into< $inner:ty >;
        $($rest:tt)*
    ) => {
        $(#[$meta])*
        pub fn $name<T>(mut self, $name: T) -> Self
        where
            T: Into<$inner>,
        {
            self.$name = $name.into();
            self
        }
        $crate::setters!($($rest)*);
    };

    // impl Into + no rename (default = Some)
    (
        $(#[$meta:meta])*
        $name:ident : impl Into< $inner:ty >;
        $($rest:tt)*
    ) => {
        $(#[$meta])*
        pub fn $name<T>(mut self, $name: T) -> Self
        where
            T: Into<$inner>,
        {
            self.$name = Some($name.into());
            self
        }
        $crate::setters!($($rest)*);
    };

    // === Plain type arms ===

    // plain + <direct> + rename
    (
        $(#[$meta:meta])*
        $method:ident < direct > -> $field:ident : $ty:ty;
        $($rest:tt)*
    ) => {
        $(#[$meta])*
        pub fn $method(mut self, $field: $ty) -> Self {
            self.$field = $field;
            self
        }
        $crate::setters!($($rest)*);
    };

    // plain + rename (default = Some)
    (
        $(#[$meta:meta])*
        $method:ident -> $field:ident : $ty:ty;
        $($rest:tt)*
    ) => {
        $(#[$meta])*
        pub fn $method(mut self, $field: $ty) -> Self {
            self.$field = Some($field);
            self
        }
        $crate::setters!($($rest)*);
    };

    // plain + <direct> + no rename
    (
        $(#[$meta:meta])*
        $name:ident < direct > : $ty:ty;
        $($rest:tt)*
    ) => {
        $(#[$meta])*
        pub fn $name(mut self, $name: $ty) -> Self {
            self.$name = $name;
            self
        }
        $crate::setters!($($rest)*);
    };

    // plain + no rename (default = Some)
    (
        $(#[$meta:meta])*
        $name:ident : $ty:ty;
        $($rest:tt)*
    ) => {
        $(#[$meta])*
        pub fn $name(mut self, $name: $ty) -> Self {
            self.$name = Some($name);
            self
        }
        $crate::setters!($($rest)*);
    };

    // Base case
    () => {};
}

/// Generates mutation setter methods in batch.
///
/// Each entry produces a `pub fn name(&mut self, ...)` method (no return value).
/// Default behavior wraps the value in `Some()`. Use `<direct>` to skip wrapping.
///
/// # Syntax
///
/// Same as [`setters!`] but generates `&mut self` methods instead of builder methods.
///
/// ```ignore
/// mut_setters! {
///     /// doc comment
///     set_name<direct> -> name: String;     // self.name = name
///     set_field -> field: Type;             // self.field = Some(field)
/// }
/// ```
#[macro_export]
macro_rules! mut_setters {
    // === impl Into<T> arms ===

    // impl Into + <direct> + rename
    (
        $(#[$meta:meta])*
        $method:ident < direct > -> $field:ident : impl Into< $inner:ty >;
        $($rest:tt)*
    ) => {
        $(#[$meta])*
        pub fn $method<T>(&mut self, $field: T)
        where
            T: Into<$inner>,
        {
            self.$field = $field.into();
        }
        $crate::mut_setters!($($rest)*);
    };

    // impl Into + rename (default = Some)
    (
        $(#[$meta:meta])*
        $method:ident -> $field:ident : impl Into< $inner:ty >;
        $($rest:tt)*
    ) => {
        $(#[$meta])*
        pub fn $method<T>(&mut self, $field: T)
        where
            T: Into<$inner>,
        {
            self.$field = Some($field.into());
        }
        $crate::mut_setters!($($rest)*);
    };

    // impl Into + <direct> + no rename
    (
        $(#[$meta:meta])*
        $name:ident < direct > : impl Into< $inner:ty >;
        $($rest:tt)*
    ) => {
        $(#[$meta])*
        pub fn $name<T>(&mut self, $name: T)
        where
            T: Into<$inner>,
        {
            self.$name = $name.into();
        }
        $crate::mut_setters!($($rest)*);
    };

    // impl Into + no rename (default = Some)
    (
        $(#[$meta:meta])*
        $name:ident : impl Into< $inner:ty >;
        $($rest:tt)*
    ) => {
        $(#[$meta])*
        pub fn $name<T>(&mut self, $name: T)
        where
            T: Into<$inner>,
        {
            self.$name = Some($name.into());
        }
        $crate::mut_setters!($($rest)*);
    };

    // === Plain type arms ===

    // plain + <direct> + rename
    (
        $(#[$meta:meta])*
        $method:ident < direct > -> $field:ident : $ty:ty;
        $($rest:tt)*
    ) => {
        $(#[$meta])*
        pub fn $method(&mut self, $field: $ty) {
            self.$field = $field;
        }
        $crate::mut_setters!($($rest)*);
    };

    // plain + rename (default = Some)
    (
        $(#[$meta:meta])*
        $method:ident -> $field:ident : $ty:ty;
        $($rest:tt)*
    ) => {
        $(#[$meta])*
        pub fn $method(&mut self, $field: $ty) {
            self.$field = Some($field);
        }
        $crate::mut_setters!($($rest)*);
    };

    // plain + <direct> + no rename
    (
        $(#[$meta:meta])*
        $name:ident < direct > : $ty:ty;
        $($rest:tt)*
    ) => {
        $(#[$meta])*
        pub fn $name(&mut self, $name: $ty) {
            self.$name = $name;
        }
        $crate::mut_setters!($($rest)*);
    };

    // plain + no rename (default = Some)
    (
        $(#[$meta:meta])*
        $name:ident : $ty:ty;
        $($rest:tt)*
    ) => {
        $(#[$meta])*
        pub fn $name(&mut self, $name: $ty) {
            self.$name = Some($name);
        }
        $crate::mut_setters!($($rest)*);
    };

    // Base case
    () => {};
}

/// Generates reference getter methods in batch.
///
/// Each entry produces a `pub fn name(&self) -> Option<&T>` method
/// that returns `self.field.as_ref()`.
///
/// # Syntax
///
/// ```ignore
/// ref_getters! {
///     /// doc comment
///     name: Type;              // pub fn name(&self) -> Option<&Type> { self.name.as_ref() }
///     method -> field: Type;   // pub fn method(&self) -> Option<&Type> { self.field.as_ref() }
/// }
/// ```
#[macro_export]
macro_rules! ref_getters {
    // With rename
    (
        $(#[$meta:meta])*
        $method:ident -> $field:ident : $ty:ty;
        $($rest:tt)*
    ) => {
        $(#[$meta])*
        pub fn $method(&self) -> Option<&$ty> {
            self.$field.as_ref()
        }
        $crate::ref_getters!($($rest)*);
    };

    // Without rename
    (
        $(#[$meta:meta])*
        $name:ident : $ty:ty;
        $($rest:tt)*
    ) => {
        $(#[$meta])*
        pub fn $name(&self) -> Option<&$ty> {
            self.$name.as_ref()
        }
        $crate::ref_getters!($($rest)*);
    };

    // Base case
    () => {};
}
