use super::*;

pub(crate) fn test_context_line_ranges(ast: &syn::File) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    for item in &ast.items {
        collect_test_context_line_ranges(item, false, &mut ranges);
    }
    ranges
}

pub(crate) fn collect_test_context_line_ranges(
    item: &Item,
    test_context: bool,
    ranges: &mut Vec<(usize, usize)>,
) {
    match item {
        Item::Fn(item_fn) => collect_function_test_range(item, item_fn, test_context, ranges),
        Item::Impl(item_impl) => collect_impl_test_ranges(item, item_impl, test_context, ranges),
        Item::Mod(item_mod) => collect_module_test_ranges(item, item_mod, test_context, ranges),
        _ => {
            if test_context {
                push_item_line_range(item, ranges);
            }
        }
    }
}

pub(crate) fn collect_function_test_range(
    item: &Item,
    item_fn: &syn::ItemFn,
    test_context: bool,
    ranges: &mut Vec<(usize, usize)>,
) {
    if test_context || has_test_attr(&item_fn.attrs) || has_cfg_test_attr(&item_fn.attrs) {
        push_item_line_range(item, ranges);
    }
}

pub(crate) fn collect_impl_test_ranges(
    item: &Item,
    item_impl: &syn::ItemImpl,
    test_context: bool,
    ranges: &mut Vec<(usize, usize)>,
) {
    let item_test_context =
        test_context || has_test_attr(&item_impl.attrs) || has_cfg_test_attr(&item_impl.attrs);
    if item_test_context {
        push_item_line_range(item, ranges);
    }
    for impl_item in &item_impl.items {
        if let ImplItem::Fn(method) = impl_item {
            collect_impl_method_test_range(method, item_test_context, ranges);
        }
    }
}

pub(crate) fn collect_impl_method_test_range(
    method: &syn::ImplItemFn,
    item_test_context: bool,
    ranges: &mut Vec<(usize, usize)>,
) {
    if item_test_context || has_test_attr(&method.attrs) || has_cfg_test_attr(&method.attrs) {
        push_span_line_range(method.span(), ranges);
    }
}

pub(crate) fn collect_module_test_ranges(
    item: &Item,
    item_mod: &syn::ItemMod,
    test_context: bool,
    ranges: &mut Vec<(usize, usize)>,
) {
    let item_test_context = test_context || is_test_module(item_mod);
    if item_test_context {
        push_item_line_range(item, ranges);
    }
    if let Some((_, items)) = &item_mod.content {
        for nested in items {
            collect_test_context_line_ranges(nested, item_test_context, ranges);
        }
    }
}

pub(crate) fn push_item_line_range(item: &Item, ranges: &mut Vec<(usize, usize)>) {
    push_span_line_range(item.span(), ranges);
}

pub(crate) fn push_span_line_range(span: proc_macro2::Span, ranges: &mut Vec<(usize, usize)>) {
    let start = line_from_span(span.start());
    let end = line_from_span(span.end()).max(start);
    ranges.push((start, end));
}

pub(crate) fn line_in_ranges(line: usize, ranges: &[(usize, usize)]) -> bool {
    ranges
        .iter()
        .any(|(start, end)| (*start..=*end).contains(&line))
}
