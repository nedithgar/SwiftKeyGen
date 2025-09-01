# RawSpan

**Structure**

> RawSpan represents a contiguous region of memory which contains initialized bytes.

**Availability:**
* iOS 12.2+
* iPadOS 12.2+
* Mac Catalyst 12.2+
* macOS 10.14.4+
* tvOS 12.2+
* visionOS 1.0+
* watchOS 5.2+

```swift
@frozen struct RawSpan
```

## Overview

A RawSpan instance is a non-owning, non-escaping view into memory. When a RawSpan is created, it inherits the lifetime of the container owning the contiguous memory, ensuring temporal safety and avoiding use-after-free errors. Operations on RawSpan are bounds-checked, ensuring spatial safety and avoiding buffer overflow errors.

## Topics

### Initializers

* `init()`: 

### Instance Properties

* `var byteCount: Int`: The number of bytes in the span.
* `var byteOffsets: Range<Int>`: The indices that are valid for subscripting the span, in ascending order.
* `var isEmpty: Bool`: A Boolean value indicating whether the span is empty.

### Instance Methods

* `func byteOffsets(of: borrowing RawSpan) -> Range<Int>? span self`: func byteOffsets(of: borrowing RawSpan) -> Range<Int>? Returns the offsets where the memory of span is located within the memory represented by self
* `func extracting(Range<Int>) -> RawSpan`: Constructs a new span over the bytes within the supplied range of positions within this span.
* `func extracting((UnboundedRange_) -> ()) -> RawSpan`: Constructs a new span over all the bytes of this span.
* `func extracting(some RangeExpression<Int>) -> RawSpan`: Constructs a new span over the bytes within the supplied range of positions within this span.
* `func extracting(droppingFirst: Int) -> RawSpan`: Returns a span over all but the given number of initial bytes.
* `func extracting(droppingLast: Int) -> RawSpan`: Returns a span over all but the given number of trailing bytes.
* `func extracting(first: Int) -> RawSpan`: Returns a span containing the initial bytes of this span, up to the specified maximum byte count.
* `func extracting(last: Int) -> RawSpan`: Returns a span containing the trailing bytes of the span, up to the given maximum length.
* `func extracting(unchecked: ClosedRange<Int>) -> RawSpan`: Constructs a new span over the bytes within the supplied range of positions within this span.
* `func extracting(unchecked: Range<Int>) -> RawSpan`: Constructs a new span over the bytes within the supplied range of positions within this span.
* `func isIdentical(to: RawSpan) -> Bool RawSpan`: func isIdentical(to: RawSpan) -> Bool Returns a Boolean value indicating whether two RawSpan instances refer to the same region in memory.
* `func unsafeLoad<T>(fromByteOffset: Int, as: T.Type) -> T`: Returns a new instance of the given type, constructed from the raw memory at the specified offset.
* `func unsafeLoad<T>(fromUncheckedByteOffset: Int, as: T.Type) -> T`: Returns a new instance of the given type, constructed from the raw memory at the specified offset.
* `func unsafeLoadUnaligned<T>(fromByteOffset: Int, as: T.Type) -> T`: Returns a new instance of the given type, constructed from the raw memory at the specified offset.
* `func unsafeLoadUnaligned<T>(fromUncheckedByteOffset: Int, as: T.Type) -> T`: Returns a new instance of the given type, constructed from the raw memory at the specified offset.
* `func withUnsafeBytes<E, Result>((UnsafeRawBufferPointer) throws(E) -> Result) throws(E) -> Result`: Calls the given closure with a pointer to the underlying bytes of the viewed contiguous storage.

## Relationships

### Conforms To

* `BitwiseCopyable`: 
* `Sendable`: 
* `SendableMetatype`: 

## See Also

### Safe Memory Access

* `struct Span Span<Element> Element`: struct Span Span<Element> represents a contiguous region of memory which contains initialized instances of Element.
* `struct OutputSpan`: 
* `struct UTF8Span`: A borrowed view into contiguous memory that contains validly-encoded UTF-8 code units.
* `struct MutableSpan`: 
* `struct MutableRawSpan`: 

