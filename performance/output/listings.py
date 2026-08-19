"""Parser/dataset/category listing printers (`list-parsers`, `list-categories`)."""

from __future__ import annotations

from .theme import BULLET, Ansi, muted, style


def print_parser_availability(adapters) -> None:
    for adapter in adapters:
        if adapter.available:
            status = style(f"{'available':<11}", Ansi.GREEN)
        else:
            status = style(f"{'unavailable':<11}", Ansi.DIM, Ansi.RED)

        tags = muted(f"[{', '.join(sorted(adapter.tags))}]") if adapter.tags else ""

        print(f"  {muted(BULLET)} {adapter.name:<15} {status} {adapter.description:<45} {tags}")

        if not adapter.available and adapter.unavailable_reason:
            print(f"      {muted(adapter.unavailable_reason)}")


def print_categories(categories: list[str], adapters) -> None:
    """One row per known tag, with the (available) adapter names carrying it."""
    if not categories:
        print("No categories registered.")
        return

    for category in categories:
        names = sorted(adapter.name for adapter in adapters if category in adapter.tags and adapter.available)
        print(f"  {muted(BULLET)} {category:<15} {', '.join(names)}")


def print_dataset_list(datasets) -> None:
    print(f"\n{style('Datasets:', Ansi.BOLD)}")
    for dataset in datasets:
        print(f"  {muted(BULLET)} {dataset.name:<18} {dataset.size:>8,} URLs")
