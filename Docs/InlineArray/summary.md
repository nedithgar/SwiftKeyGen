# InlineArray Summary

A concise capability and constraint overview extracted from the InlineArray documentation files.

## Cheat-Sheet (Usage Quick Reference)

Initialization:
- Literal: `let a: InlineArray<4, UInt8> = [0,1,2,3]` (count and Element can both be inferred)
- Index-based: `let arr = try InlineArray<16, UInt8> { i in UInt8(truncatingIfNeeded: i) }`
- Progressive (depends on previous element): `let fib = try InlineArray<8, Int>( first: 0 ) { prev in prev + 1 }`
- Repeating value: `let zeros = InlineArray<32, UInt8>(repeating: 0)`
- Bulk initializer span: `let buf = try InlineArray<32, UInt8>(initializingWith: { span in /* write into span */ })`

Indexing & Iteration:
- Iterate indices: `for i in array.indices { ... }`
- Direct access: `array[i]` (bounds checked) / `array[unchecked: i]` (unchecked, caller must guarantee validity)
- Start/End: `array.startIndex == 0`, `array.endIndex == count`
- Manual advance: `let j = array.index(after: i)` / `let k = array.index(before: i)`

Spans & Unsafe Access:
- Read-only contiguous view: `array.span`
- Mutable contiguous view: `array.mutableSpan` (requires `var` binding; returns a `MutableSpan<Element>`)
- Use spans for interoperability and bulk operations without copying.

Mutation:
- Per-element write via subscript set: `array[i] = value`
- Swap: `array.swapAt(i, j)`
- Bulk mutate: `array.mutableSpan` in closure/context.

Not Supported (by design):
- Dynamic resizing (no `append`, `removeLast`, capacity management)
- Changing `count` at runtime (count is a compile-time constant generic parameter)
- Copy-on-write semantics (storage is always inline, value semantics rely on full copy of inline storage)

Performance Tips:
- Prefer span-based bulk writes during initialization for fewer per-element operations.
- Use `unchecked` subscript only in provably safe hot paths (tight crypto loops) to eliminate bounds checks.
- Inline layout improves cache locality for small fixed-size buffers vs heap-allocated `Array`.

## Capabilities
- Fixed-size, contiguous storage inline with the containing value (no heap allocation for elements).
- Array literal initialization with inference for `count` and/or `Element`.
- Multiple initialization strategies:
  * Index-driven closure initializer.
  * First+next progressive initializer (stateful generation sequence).
  * Bulk span-based initializer permitting in-place writes.
  * Repeating value initializer.
- Random-access indexing using `Int` indices (typealias of `Index = Int`).
- Standard collection-like introspection: `count`, `isEmpty`, `startIndex`, `endIndex`, `indices`.
- Safe element access with bounds checking; optional unchecked variant for performance-critical sections.
- Elementary mutations: element assignment, `swapAt`.
- Efficient contiguous read-only and mutable slice exposure via `span` / `mutableSpan`.
- Conforms to `Copyable`, `BitwiseCopyable` (when Element permits), and `Sendable` enabling safe value passing across concurrency boundaries given element constraints.

## Constraints / Limitations
- Size (`count`) is a generic compile-time constant; cannot vary per-instance.
- `isEmpty` is effectively `count == 0`; all instances of the same `InlineArray<count, Element>` share emptiness semantics (no dynamic growth/shrink).
- Memory footprint is `stride(Element) * count` (except zero when `count == 0`). No over-allocation or capacity slack.
- No APIs for insertion/removal or reallocation.
- Initialization closures must produce exactly one element per index; failure aborts initialization (propagates thrown error); no partial initialization state is exposed.
- Progressive initializer requires producing the remaining `count-1` elements based on the prior value; cannot short-circuit early.
- Bulk `initializingWith` requires writing all elements to provided `OutputSpan`; responsibility on caller to fully initialize.
- `mutableSpan` requires unique mutable access to the InlineArray value (enforced by Swift's borrow checker / exclusivity rules).
- Unchecked subscript requires caller to ensure index validity (`0 <= i < count`); violating leads to undefined behavior.

## Indexing Guarantees
- Valid indices: `0 ..< count`; `endIndex == count` (not valid for subscript read/write).
- `startIndex == 0` when `count > 0`; if `count == 0`, `startIndex == endIndex == 0`.
- `index(after: i)` valid iff `i < endIndex`; result is `i + 1`.
- `index(before: i)` valid iff `i > startIndex`; result is `i - 1`.
- `indices` returns the half-open range of valid subscript indices.

## Mutability Rules
- Mutation of elements via setter or `swapAt` requires the InlineArray binding to be a `var`.
- `mutableSpan` acquisition is `mutating` and enforces exclusive access.
- No structural mutations (count is immutable); only element value changes.
- Value-copy semantics copy the full inline storage (cost proportional to element size * count).

## Performance Notes
- No heap allocation overhead (unlike `Array`) -> predictable constant construction and copy costs.
- Improved cache locality for small fixed sizes (e.g., cryptographic blocks, digests, nonces).
- Eliminates copy-on-write branching; copies always occur on value assignment or pass-by-value.
- Bounds-checked subscript incurs the usual check; unchecked variant can remove this in critical loops.
- Span exposure avoids temporary array creation for APIs expecting contiguous storage views.
- Zero-sized types are optimized: size 0, stride 1, alignment 1.

## Recommended Usage Patterns
- Replace small fixed-size `[UInt8]` buffers (<= 64 bytes) used transiently in cryptographic code.
- Use progressive initializer for deterministic sequences (e.g., counters, derived constants).
- Use repeating initializer for zeroing or constant fill (e.g., nonce buffers).
- Use bulk span initializer for bridging with C APIs performing in-place writes.

## Anti-Patterns / Misuse
- Attempting dynamic collection operations (append/remove) — redesign algorithms for fixed-size or fall back to `Array`.
- Partial initialization or leaving elements uninitialized in `initializingWith` — must fully write all.
- Overusing unchecked subscript without rigorous proof — keep within tight, audited loops.
- Using large counts (hundreds/thousands) where stack frame bloat or copy overhead outweighs benefits; prefer heap-backed containers there.

## Security Considerations
- Predictable, inline layout simplifies secure zeroization: implement helper to overwrite sensitive contents explicitly.
- Absence of spare capacity reduces risk of leftover data leakage beyond logical count.

## Migration Notes for This Repository
- Introduce helper bridging APIs (planned): `asArray()`, `withUnsafeBufferPointer(_:)`, `overwrite(with:)`.
- Limit initial adoption to internal crypto/temp buffers to avoid public API breakage.
- Benchmark before/after to validate claimed locality and reduced heap traffic.

## Source of Truth
Derived from the documentation files located in `Docs/InlineArray/`:
- inlinearray.md
- init(_:).md
- init(first:next:).md
- init(initializingwith:).md
- init(repeating:).md
- subscript(_:).md
- index.md
- startindex.md
- endindex.md
- index(after:).md
- index(before:).md
- indices.md
- count.md
- isempty.md
- swapat(_:_:).md
- span.md
- mutablespan.md
- element.md
