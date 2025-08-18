# Span

**Structure**

> Span<Element> represents a contiguous region of memory which contains initialized instances of Element.

**Availability:**
* iOS 12.2+
* iPadOS 12.2+
* Mac Catalyst 12.2+
* macOS 10.14.4+
* tvOS 12.2+
* visionOS 1.0+
* watchOS 5.2+

```swift
@frozen struct Span<Element> where Element : ~Copyable
```

## Overview

A Span instance is a non-owning, non-escaping view into memory. When a Span is created, it inherits the lifetime of the container owning the contiguous memory, ensuring temporal safety and avoiding use-after-free errors. Operations on Span are bounds-checked, ensuring spatial safety and avoiding buffer overflow errors.

## Topics

### Initializers

* `init()`: 

### Instance Properties

* `var bytes: RawSpan`: 
* `var count: Int`: The number of elements in the span.
* `var indices: Range<Span<Element>.Index>`: The indices that are valid for subscripting the span, in ascending order.
* `var isEmpty: Bool`: A Boolean value indicating whether the span is empty.

### Instance Methods

* `func extracting(Range<Span<Element>.Index>) -> Span<Element>`: Constructs a new span over the items within the supplied range of positions within this span.
* `func extracting(some RangeExpression<Int>) -> Span<Element>`: Constructs a new span over the items within the supplied range of positions within this span.
* `func extracting((UnboundedRange_) -> ()) -> Span<Element>`: Constructs a new span over all the items of this span.
* `func extracting(droppingFirst: Int) -> Span<Element>`: Returns a span over all but the given number of initial elements.
* `func extracting(droppingLast: Int) -> Span<Element>`: Returns a span over all but the given number of trailing elements.
* `func extracting(first: Int) -> Span<Element>`: Returns a span containing the initial elements of this span, up to the specified maximum length.
* `func extracting(last: Int) -> Span<Element>`: Returns a span containing the final elements of the span, up to the given maximum length.
* `func extracting(unchecked: ClosedRange<Span<Element>.Index>) -> Span<Element>`: Constructs a new span over the items within the supplied range of positions within this span.
* `func extracting(unchecked: Range<Span<Element>.Index>) -> Span<Element>`: Constructs a new span over the items within the supplied range of positions within this span.
* `func indices(of: borrowing Span<Element>) -> Range<Span<Element>.Index>? self span nil span self`: func indices(of: borrowing Span<Element>) -> Range<Span<Element>.Index>? Returns the indices within self where the memory represented by span is located, or nil if span is not located within self.
* `func isIdentical(to: Span<Element>) -> Bool Span`: func isIdentical(to: Span<Element>) -> Bool Returns a Boolean value indicating whether two Span instances refer to the same region in memory.
* `func withUnsafeBufferPointer<E, Result>((UnsafeBufferPointer<Element>) throws(E) -> Result) throws(E) -> Result`: Calls a closure with a pointer to the viewed contiguous storage.
* `func withUnsafeBytes<E, Result>((UnsafeRawBufferPointer) throws(E) -> Result) throws(E) -> Result`: Calls the given closure with a pointer to the underlying bytes of the viewed contiguous storage.

### Subscripts

* `subscript(Span<Element>.Index) -> Element Span`: subscript(Span<Element>.Index) -> Element Accesses the element at the specified position in the Span.
* `subscript(Span<Element>.Index) -> Element Span`: subscript(Span<Element>.Index) -> Element Accesses the element at the specified position in the Span.
* `subscript(unchecked _: Span<Element>.Index) -> Element Span`: subscript(unchecked _: Span<Element>.Index) -> Element Accesses the element at the specified position in the Span.
* `subscript(unchecked _: Span<Element>.Index) -> Element Span`: subscript(unchecked _: Span<Element>.Index) -> Element Accesses the element at the specified position in the Span.

### Type Aliases

* `typealias Index Span`: typealias Index The representation for a position in Span.

## Relationships

### Conforms To

* `BitwiseCopyable`: 
* `Sendable Element Escapable Sendable`: Sendable
* `SendableMetatype Element Escapable Sendable`: SendableMetatype

## See Also

### Safe Memory Access

* `struct RawSpan RawSpan`: represents a contiguous region of memory which contains initialized bytes.
* `struct OutputSpan`: 
* `struct UTF8Span`: A borrowed view into contiguous memory that contains validly-encoded UTF-8 code units.
* `struct MutableSpan`: 
* `struct MutableRawSpan`: 

