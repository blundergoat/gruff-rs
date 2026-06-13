use super::*;

pub(crate) struct ProjectIndexBuilders<'a> {
    pub(crate) modules: &'a mut Vec<ModuleSummary>,
    pub(crate) items: &'a mut Vec<ItemSummary>,
    pub(crate) call_names: &'a mut Vec<CallNameSummary>,
}

pub(crate) fn collect_project_rust_index(
    file: &SourceFile,
    source: &str,
    ast: &syn::File,
    module_path: &str,
    builders: ProjectIndexBuilders<'_>,
) {
    let scope = ProjectItemScope {
        file,
        module_path,
        cfg_context: false,
        test_context: false,
        allow_dead_code_context: false,
    };
    collect_project_items(scope, &ast.items, builders.modules, builders.items);
    collect_call_names(file, source, builders.call_names);
}

pub(crate) fn collect_project_items(
    scope: ProjectItemScope<'_>,
    syn_items: &[Item],
    modules: &mut Vec<ModuleSummary>,
    items: &mut Vec<ItemSummary>,
) {
    for item in syn_items {
        collect_project_item(scope, item, modules, items);
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ProjectItemScope<'a> {
    pub(crate) file: &'a SourceFile,
    pub(crate) module_path: &'a str,
    pub(crate) cfg_context: bool,
    pub(crate) test_context: bool,
    pub(crate) allow_dead_code_context: bool,
}

pub(crate) fn collect_project_item(
    scope: ProjectItemScope<'_>,
    item: &Item,
    modules: &mut Vec<ModuleSummary>,
    items: &mut Vec<ItemSummary>,
) {
    match item {
        Item::Fn(item_fn) => collect_project_function(scope, item_fn, items),
        Item::Struct(item_struct) => collect_project_struct(scope, item_struct, items),
        Item::Enum(item_enum) => collect_project_enum(scope, item_enum, items),
        Item::Trait(item_trait) => collect_project_trait(scope, item_trait, items),
        Item::Const(item_const) => collect_project_const(scope, item_const, items),
        Item::Static(item_static) => collect_project_static(scope, item_static, items),
        Item::Type(item_type) => collect_project_type_alias(scope, item_type, items),
        Item::Impl(item_impl) => collect_project_impl(scope, item_impl, items),
        Item::Mod(item_mod) => collect_project_module(scope, item_mod, modules, items),
        _ => {}
    }
}

pub(crate) fn collect_project_function(
    scope: ProjectItemScope<'_>,
    item_fn: &syn::ItemFn,
    items: &mut Vec<ItemSummary>,
) {
    items.push(project_item(
        scope,
        item_fn.sig.ident.to_string(),
        "function",
        line_from_span(item_fn.sig.ident.span().start()),
        ProjectItemContext {
            public: visibility_is_public(&item_fn.vis),
            externally_public: visibility_is_externally_public(&item_fn.vis),
            cfg_gated: scope.cfg_context || has_cfg_attr(&item_fn.attrs),
            test_context: scope.test_context
                || has_test_attr(&item_fn.attrs)
                || has_cfg_test_attr(&item_fn.attrs),
            container: None,
            trait_impl: false,
            exported_by_attr: has_export_attr(&item_fn.attrs),
            allow_dead_code: scope.allow_dead_code_context
                || has_allow_dead_code_attr(&item_fn.attrs),
        },
    ));
}

pub(crate) fn collect_project_struct(
    scope: ProjectItemScope<'_>,
    item_struct: &syn::ItemStruct,
    items: &mut Vec<ItemSummary>,
) {
    items.push(project_item(
        scope,
        item_struct.ident.to_string(),
        "struct",
        line_from_span(item_struct.ident.span().start()),
        ProjectItemContext {
            public: visibility_is_public(&item_struct.vis),
            externally_public: visibility_is_externally_public(&item_struct.vis),
            cfg_gated: scope.cfg_context || has_cfg_attr(&item_struct.attrs),
            test_context: scope.test_context || has_cfg_test_attr(&item_struct.attrs),
            container: None,
            trait_impl: false,
            exported_by_attr: has_export_attr(&item_struct.attrs),
            allow_dead_code: scope.allow_dead_code_context
                || has_allow_dead_code_attr(&item_struct.attrs),
        },
    ));
}

pub(crate) fn collect_project_enum(
    scope: ProjectItemScope<'_>,
    item_enum: &syn::ItemEnum,
    items: &mut Vec<ItemSummary>,
) {
    items.push(project_item(
        scope,
        item_enum.ident.to_string(),
        "enum",
        line_from_span(item_enum.ident.span().start()),
        ProjectItemContext {
            public: visibility_is_public(&item_enum.vis),
            externally_public: visibility_is_externally_public(&item_enum.vis),
            cfg_gated: scope.cfg_context || has_cfg_attr(&item_enum.attrs),
            test_context: scope.test_context || has_cfg_test_attr(&item_enum.attrs),
            container: None,
            trait_impl: false,
            exported_by_attr: has_export_attr(&item_enum.attrs),
            allow_dead_code: scope.allow_dead_code_context
                || has_allow_dead_code_attr(&item_enum.attrs),
        },
    ));
}

pub(crate) fn collect_project_trait(
    scope: ProjectItemScope<'_>,
    item_trait: &syn::ItemTrait,
    items: &mut Vec<ItemSummary>,
) {
    items.push(project_item(
        scope,
        item_trait.ident.to_string(),
        "trait",
        line_from_span(item_trait.ident.span().start()),
        ProjectItemContext {
            public: visibility_is_public(&item_trait.vis),
            externally_public: visibility_is_externally_public(&item_trait.vis),
            cfg_gated: scope.cfg_context || has_cfg_attr(&item_trait.attrs),
            test_context: scope.test_context || has_cfg_test_attr(&item_trait.attrs),
            container: None,
            trait_impl: false,
            exported_by_attr: has_export_attr(&item_trait.attrs),
            allow_dead_code: scope.allow_dead_code_context
                || has_allow_dead_code_attr(&item_trait.attrs),
        },
    ));
}

pub(crate) fn collect_project_const(
    scope: ProjectItemScope<'_>,
    item_const: &syn::ItemConst,
    items: &mut Vec<ItemSummary>,
) {
    items.push(project_item(
        scope,
        item_const.ident.to_string(),
        "const",
        line_from_span(item_const.ident.span().start()),
        ProjectItemContext {
            public: visibility_is_public(&item_const.vis),
            externally_public: visibility_is_externally_public(&item_const.vis),
            cfg_gated: scope.cfg_context || has_cfg_attr(&item_const.attrs),
            test_context: scope.test_context || has_cfg_test_attr(&item_const.attrs),
            container: None,
            trait_impl: false,
            exported_by_attr: has_export_attr(&item_const.attrs),
            allow_dead_code: scope.allow_dead_code_context
                || has_allow_dead_code_attr(&item_const.attrs),
        },
    ));
}

pub(crate) fn collect_project_static(
    scope: ProjectItemScope<'_>,
    item_static: &syn::ItemStatic,
    items: &mut Vec<ItemSummary>,
) {
    items.push(project_item(
        scope,
        item_static.ident.to_string(),
        "static",
        line_from_span(item_static.ident.span().start()),
        ProjectItemContext {
            public: visibility_is_public(&item_static.vis),
            externally_public: visibility_is_externally_public(&item_static.vis),
            cfg_gated: scope.cfg_context || has_cfg_attr(&item_static.attrs),
            test_context: scope.test_context || has_cfg_test_attr(&item_static.attrs),
            container: None,
            trait_impl: false,
            exported_by_attr: has_export_attr(&item_static.attrs),
            allow_dead_code: scope.allow_dead_code_context
                || has_allow_dead_code_attr(&item_static.attrs),
        },
    ));
}

pub(crate) fn collect_project_type_alias(
    scope: ProjectItemScope<'_>,
    item_type: &syn::ItemType,
    items: &mut Vec<ItemSummary>,
) {
    items.push(project_item(
        scope,
        item_type.ident.to_string(),
        "type alias",
        line_from_span(item_type.ident.span().start()),
        ProjectItemContext {
            public: visibility_is_public(&item_type.vis),
            externally_public: visibility_is_externally_public(&item_type.vis),
            cfg_gated: scope.cfg_context || has_cfg_attr(&item_type.attrs),
            test_context: scope.test_context || has_cfg_test_attr(&item_type.attrs),
            container: None,
            trait_impl: false,
            exported_by_attr: has_export_attr(&item_type.attrs),
            allow_dead_code: scope.allow_dead_code_context
                || has_allow_dead_code_attr(&item_type.attrs),
        },
    ));
}

pub(crate) fn collect_project_impl(
    scope: ProjectItemScope<'_>,
    item_impl: &syn::ItemImpl,
    items: &mut Vec<ItemSummary>,
) {
    for impl_item in &item_impl.items {
        if let ImplItem::Fn(method) = impl_item {
            collect_project_method(scope, item_impl, method, items);
        }
    }
}

pub(crate) fn collect_project_method(
    scope: ProjectItemScope<'_>,
    item_impl: &syn::ItemImpl,
    method: &syn::ImplItemFn,
    items: &mut Vec<ItemSummary>,
) {
    items.push(project_item(
        scope,
        method.sig.ident.to_string(),
        "method",
        line_from_span(method.sig.ident.span().start()),
        ProjectItemContext {
            public: visibility_is_public(&method.vis),
            externally_public: visibility_is_externally_public(&method.vis),
            cfg_gated: scope.cfg_context
                || has_cfg_attr(&item_impl.attrs)
                || has_cfg_attr(&method.attrs),
            test_context: scope.test_context
                || has_test_attr(&item_impl.attrs)
                || has_cfg_test_attr(&item_impl.attrs)
                || has_test_attr(&method.attrs)
                || has_cfg_test_attr(&method.attrs),
            container: impl_self_type_name(item_impl),
            trait_impl: item_impl.trait_.is_some(),
            exported_by_attr: has_export_attr(&method.attrs),
            allow_dead_code: scope.allow_dead_code_context
                || has_allow_dead_code_attr(&item_impl.attrs)
                || has_allow_dead_code_attr(&method.attrs),
        },
    ));
}

pub(crate) fn collect_project_module(
    scope: ProjectItemScope<'_>,
    item_mod: &syn::ItemMod,
    modules: &mut Vec<ModuleSummary>,
    items: &mut Vec<ItemSummary>,
) {
    let current_module = module_name(scope.module_path, &item_mod.ident.to_string());
    let module_cfg_gated = scope.cfg_context || has_cfg_attr(&item_mod.attrs);
    let module_test_context = scope.test_context || is_test_module(item_mod);
    let module_allow_dead_code =
        scope.allow_dead_code_context || has_allow_dead_code_attr(&item_mod.attrs);
    modules.push(ModuleSummary {
        file_path: scope.file.display_path.clone(),
        module_path: current_module.clone(),
        line: line_from_span(item_mod.ident.span().start()),
        public: visibility_is_public(&item_mod.vis),
        inline: item_mod.content.is_some(),
        cfg_gated: module_cfg_gated,
    });
    if let Some((_, nested)) = &item_mod.content {
        let nested_scope = ProjectItemScope {
            file: scope.file,
            module_path: &current_module,
            cfg_context: module_cfg_gated,
            test_context: module_test_context,
            allow_dead_code_context: module_allow_dead_code,
        };
        collect_project_items(nested_scope, nested, modules, items);
    }
}

pub(crate) fn project_item(
    scope: ProjectItemScope<'_>,
    name: String,
    kind: &str,
    line: usize,
    context: ProjectItemContext,
) -> ItemSummary {
    ItemSummary {
        file_path: scope.file.display_path.clone(),
        module_path: scope.module_path.to_string(),
        name,
        kind: kind.to_string(),
        container: context.container,
        line,
        public: context.public,
        externally_public: context.externally_public,
        cfg_gated: context.cfg_gated,
        test_context: context.test_context,
        trait_impl: context.trait_impl,
        exported_by_attr: context.exported_by_attr,
        allow_dead_code: context.allow_dead_code,
    }
}

fn has_export_attr(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        let Some(segment) = attr.path().segments.last() else {
            return false;
        };
        if attr_ident_is_export(&segment.ident) {
            return true;
        }
        // Rust 2024 wraps these as `#[unsafe(no_mangle)]` / `#[unsafe(export_name = ...)]`,
        // so the attribute path is `unsafe` and the export ident sits in the inner tokens.
        if segment.ident == "unsafe" {
            if let syn::Meta::List(list) = &attr.meta {
                let inner = list.tokens.to_string();
                return inner.contains("no_mangle") || inner.contains("export_name");
            }
        }
        false
    })
}

fn attr_ident_is_export(ident: &syn::Ident) -> bool {
    ident == "no_mangle" || ident == "export_name" || ident == "pymodule" || ident == "pyfunction"
}

fn has_allow_dead_code_attr(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if !attr.path().is_ident("allow") {
            return false;
        }
        let syn::Meta::List(list) = &attr.meta else {
            return false;
        };
        list.tokens.to_string().contains("dead_code")
    })
}

fn impl_self_type_name(item_impl: &syn::ItemImpl) -> Option<String> {
    let syn::Type::Path(path) = item_impl.self_ty.as_ref() else {
        return None;
    };
    path.path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
}

pub(crate) fn module_name(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_string()
    } else {
        format!("{parent}::{name}")
    }
}

pub(crate) fn inferred_file_module_path(file: &SourceFile) -> String {
    let Some(path) = file.display_path.strip_prefix("src/") else {
        return String::new();
    };
    if matches!(path, "lib.rs" | "main.rs") {
        return String::new();
    }

    let without_extension = path
        .strip_suffix("/mod.rs")
        .or_else(|| path.strip_suffix(".rs"))
        .unwrap_or(path);
    without_extension.replace('/', "::")
}
