// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use proc_macro::TokenStream;
use quote::quote;
use syn::{DataEnum, Ident};

pub fn parse_newtype_fields(item: &syn::DeriveInput) -> (syn::Type, proc_macro2::TokenStream) {
    let fields = match item.data {
        syn::Data::Struct(ref body) => body.fields.iter().collect::<Vec<&syn::Field>>(),
        _ => vec![],
    };

    let field_ty = match fields.len() {
        1 => Some(fields[0].ty.clone()),
        _ => None,
    };
    let field_ty = field_ty.expect("#[derive(Deref)] can only be used on structs with one field.");

    let field_name = match fields[0].ident {
        Some(ref ident) => quote!(#ident),
        None => quote!(0),
    };

    match field_ty {
        syn::Type::Reference(syn::TypeReference { elem, .. }) => (*elem, quote!(self.#field_name)),
        x => (x, quote!(&self.#field_name)),
    }
}

pub fn impl_enum_tryfrom(name: &Ident, variants: &DataEnum) -> proc_macro2::TokenStream {
    // the TryFrom dispatch
    let mut try_iter = variants.variants.iter();
    let first_variant = try_iter
        .next()
        .expect("#[derive(ValidKey] requires a non-empty enum.");
    let first_variant_ident = &first_variant.ident;
    let first_variant_arg = &first_variant
        .fields
        .iter()
        .next()
        .expect("Unrecognized enum for key types")
        .ty;

    let mut try_chain = quote! {
        #first_variant_arg::try_from(bytes).and_then(|key| Ok(#name::#first_variant_ident(key)))
    };
    for variant in try_iter {
        let variant_ident = &variant.ident;
        let variant_arg = &variant
            .fields
            .iter()
            .next()
            .expect("Unrecognized enum for key types")
            .ty;
        try_chain.extend(quote!{
            .or_else(|_err| #variant_arg::try_from(bytes).and_then(|key| Ok(#name::#variant_ident(key))))
        })
    }

    quote! {
        impl core::convert::TryFrom<&[u8]> for #name {
            type Error = libra_crypto::CryptoMaterialError;
            fn try_from(bytes: &[u8]) -> std::result::Result<#name, Self::Error> {
                #try_chain
            }
        }
    }
}

fn match_enum_to_bytes(name: &Ident, variants: &DataEnum) -> proc_macro2::TokenStream {
    // the ValidKey dispatch proper
    let mut match_arms = quote! {};
    for variant in variants.variants.iter() {
        let variant_ident = &variant.ident;

        match_arms.extend(quote! {
            #name::#variant_ident(key) => key.to_bytes().to_vec(),
        });
    }
    match_arms
}

pub fn impl_enum_validkey(name: &Ident, variants: &DataEnum) -> TokenStream {
    let mut try_from = impl_enum_tryfrom(name, variants);

    let to_bytes_arms = match_enum_to_bytes(name, variants);

    try_from.extend(quote! {

        impl libra_crypto::ValidKey for #name {
            fn to_bytes(&self) -> Vec<u8> {
                match self {
                    #to_bytes_arms
                }
            }
        }
    });
    try_from.into()
}
