# OutputSpan

**Structure**

> Create an OutputSpan with zero capacity

**Availability:**
* iOS 12.2+
* iPadOS 12.2+
* Mac Catalyst 12.2+
* macOS 10.14.4+
* tvOS 12.2+
* visionOS 1.0+
* watchOS 5.2+

```swift
@frozen struct OutputSpan<Element> where Element : ~Copyable
```

## Topics

### Initializers

* `init()`: Create an OutputSpan with zero capacity
* `init(buffer: UnsafeMutableBufferPointer<Element>, initializedCount: Int)`: Unsafely create an OutputSpan over partly-initialized memory.
* `init(buffer: borrowing Slice<UnsafeMutableBufferPointer<Element>>, initializedCount: Int)`: Unsafely create an OutputSpan over partly-initialized memory.

### Instance Properties

* `let capacity: Int`: 
* `var count: Int`: The number of initialized elements in this span.
* `var freeCapacity: Int`: The number of additional elements that can be added to this span.
* `var indices: Range<OutputSpan<Element>.Index> OutputSpan`: var indices: Range<OutputSpan<Element>.Index> The range of initialized positions for this OutputSpan.
* `var isEmpty: Bool`: A Boolean value indicating whether the span is empty.
* `var isFull: Bool`: A Boolean value indicating whether the span is full.
* `var mutableSpan: MutableSpan<Element>`: Exclusively borrow the underlying initialized memory for mutation.
* `var span: Span<Element>`: Borrow the underlying initialized memory for read-only access.

### Instance Methods

* `func append(consuming Element)`: Append a single element to this span.
* `func append(repeating: Element, count: Int)`: Repeatedly append an element to this span.
* `func finalize(for: Slice<UnsafeMutableBufferPointer<Element>>) -> Int`: Consume the output span and return the number of initialized elements.
* `func finalize(for: UnsafeMutableBufferPointer<Element>) -> Int`: Consume the output span and return the number of initialized elements.
* `func removeAll()`: Remove all this span’s elements and return its memory to the uninitialized state.
* `func removeLast() -> Element`: Remove the last initialized element from this span.
* `func removeLast(Int)`: Remove the last N elements of this span, returning the memory they occupy to the uninitialized state.
* `func swapAt(OutputSpan<Element>.Index, OutputSpan<Element>.Index)`: Exchange the elements at the two given offsets
* `func swapAt(unchecked: OutputSpan<Element>.Index, unchecked: OutputSpan<Element>.Index)`: Exchange the elements at the two given offsets
* `func withUnsafeMutableBufferPointer<E, R>((UnsafeMutableBufferPointer<Element>, inout Int) throws(E) -> R) throws(E) -> R`: Call the given closure with the unsafe buffer pointer addressed by this OutputSpan and a mutable reference to its count of initialized elements.

### Subscripts

* `subscript(OutputSpan<Element>.Index) -> Element`: Accesses the element at the specified position.
* `subscript(unchecked _: OutputSpan<Element>.Index) -> Element`: Accesses the element at the specified position.

### Type Aliases

* `typealias Index OutputSpan`: typealias Index The type that represents an initialized position in an OutputSpan.

## Relationships

### Conforms To

* `Sendable Element Escapable Sendable`: Sendable
* `SendableMetatype Element Escapable Sendable`: SendableMetatype

## See Also

### Safe Memory Access

* `struct Span Span<Element> Element`: struct Span Span<Element> represents a contiguous region of memory which contains initialized instances of Element.
* `struct RawSpan RawSpan`: represents a contiguous region of memory which contains initialized bytes.
* `struct UTF8Span`: A borrowed view into contiguous memory that contains validly-encoded UTF-8 code units.
* `struct MutableSpan`: 
* `struct MutableRawSpan`: 

