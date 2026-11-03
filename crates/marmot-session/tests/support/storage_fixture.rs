/// Opt this test process into relaxed storage before creating its fixture directory.
pub(crate) fn relaxed_storage_dir() -> std::io::Result<tempfile::TempDir> {
    storage_sqlite::relax_storage_for_test_process();
    tempfile::tempdir()
}
