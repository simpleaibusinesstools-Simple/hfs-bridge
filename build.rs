fn main() {
    #[cfg(all(windows, feature = "native-mount"))]
    winfsp::build::winfsp_link_delayload();
}
