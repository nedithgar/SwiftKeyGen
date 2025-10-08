# MutableRawSpan

**Structure**

> Returns a new instance of the given type, constructed from the raw memory at the specified offset.

**Availability:**
* iOS 12.2+
* iPadOS 12.2+
* Mac Catalyst 12.2+
* macOS 10.14.4+
* tvOS 12.2+
* visionOS 1.0+
* watchOS 5.2+

```swift
@frozen struct MutableRawSpan
```

## Topics

### Initializers

* `init()`: 

### Instance Properties

* `var byteCount: Int`: 
* `var byteOffsets: Range<Int>`: 
* `var bytes: RawSpan`: 
* `var isEmpty: Bool`: 

### Instance Methods

* `func extracting(Range<Int>) -> MutableRawSpan`: 
* `func extracting(some RangeExpression<Int>) -> MutableRawSpan`: 
* `func extracting((UnboundedRange_) -> ()) -> MutableRawSpan`: 
* `func extracting(droppingFirst: Int) -> MutableRawSpan`: 
* `func extracting(droppingLast: Int) -> MutableRawSpan`: 
* `func extracting(first: Int) -> MutableRawSpan`: 
* `func extracting(last: Int) -> MutableRawSpan`: 
* `func extracting(unchecked: ClosedRange<Int>) -> MutableRawSpan`: 
* `func extracting(unchecked: Range<Int>) -> MutableRawSpan`: 
* `func storeBytes<T>(of: T, toByteOffset: Int, as: T.Type)`: 
* `func storeBytes<T>(of: T, toUncheckedByteOffset: Int, as: T.Type)`: 
* `func unsafeLoad<T>(fromByteOffset: Int, as: T.Type) -> T`: Returns a new instance of the given type, constructed from the raw memory at the specified offset.
* `func unsafeLoad<T>(fromUncheckedByteOffset: Int, as: T.Type) -> T`: Returns a new instance of the given type, constructed from the raw memory at the specified offset.
* `func unsafeLoadUnaligned<T>(fromByteOffset: Int, as: T.Type) -> T`: Returns a new instance of the given type, constructed from the raw memory at the specified offset.
* `func unsafeLoadUnaligned<T>(fromUncheckedByteOffset: Int, as: T.Type) -> T`: Returns a new instance of the given type, constructed from the raw memory at the specified offset.
* `func withUnsafeBytes<E, Result>((UnsafeRawBufferPointer) throws(E) -> Result) throws(E) -> Result`: 
* `func withUnsafeMutableBytes<E, Result>((UnsafeMutableRawBufferPointer) throws(E) -> Result) throws(E) -> Result`: 

## Relationships

### Conforms To

* `Sendable`: 
* `SendableMetatype`: 

## See Also

### Safe Memory Access

* `struct Span Span<Element> Element`: struct Span Span<Element> represents a contiguous region of memory which contains initialized instances of Element.
* `struct RawSpan RawSpan`: represents a contiguous region of memory which contains initialized bytes.
* `struct OutputSpan`: 
* `struct UTF8Span`: A borrowed view into contiguous memory that contains validly-encoded UTF-8 code units.
* `struct MutableSpan`: 

