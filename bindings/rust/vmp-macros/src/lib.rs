use proc_macro::TokenStream;

#[proc_macro_attribute]
pub fn vm_func(_attr: TokenStream, item: TokenStream) -> TokenStream {
    item
}

#[proc_macro_attribute]
pub fn vm_string(_attr: TokenStream, item: TokenStream) -> TokenStream {
    item
}
