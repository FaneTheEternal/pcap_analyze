extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn;

#[proc_macro_derive(Layer)]
pub fn layer_derive(input: TokenStream) -> TokenStream {
    let ast: syn::DeriveInput = syn::parse(input).unwrap();
    let name = &ast.ident;
    let gen = quote! {
        impl Layer for #name {
            fn name() -> &'static str where Self: Sized {
                stringify!(#name)
            }
        }
    };
    gen.into()
}
