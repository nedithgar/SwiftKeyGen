# Data

**Structure**

A byte buffer in memory.

**Availability:**
- iOS 8.0+
- iPadOS 8.0+
- Mac Catalyst 8.0+
- macOS 10.10+
- tvOS 9.0+
- visionOS 1.0+
- watchOS 2.0+

```swift
@frozen
struct Data
```

**Mentioned in:**
- Processing URL session data task results with Combine
- Encoding and Decoding Custom Types

## Overview

The `Data` value type allows simple byte buffers to take on the behavior of Foundation objects. You can create empty or pre-populated buffers from a variety of sources and later add or remove bytes. You can filter and sort the content, or compare against other buffers. You can manipulate subranges of bytes and iterate over some or all of them.

`Data` bridges to the `NSData` class and its mutable subclass, `NSMutableData`. You can use these interchangeably in code that interacts with Objective-C APIs.

## Topics

### Creating Empty Data

- `init()` - Creates an empty data buffer.
- `init(capacity: Int)` - Creates an empty data buffer of a specified size.
- `init(count: Int)` - Creates a new data buffer with the specified count of zeroed bytes.
- `func resetBytes(in: Range<Data.Index>)` - Sets a region of the data buffer to 0.

### Creating Populated Data

- `init()` - Creates an empty data buffer.
- `init<SourceType>(buffer: UnsafeBufferPointer<SourceType>)` - Creates a data buffer with copied memory content using a buffer pointer.
- `init<SourceType>(buffer: UnsafeMutableBufferPointer<SourceType>)` - Creates a data buffer with copied memory content using a mutable buffer pointer.
- `init(bytes: UnsafeRawPointer, count: Int)` - Creates data with copied memory content.
- `init(bytesNoCopy: UnsafeMutableRawPointer, count: Int, deallocator: Data.Deallocator)` - Creates a data buffer with memory content without copying the bytes.
- `init(capacity: Int)` - Creates an empty data buffer of a specified size.
- `init(count: Int)` - Creates a new data buffer with the specified count of zeroed bytes.

### Creating Data from Raw Memory

- `init(bytes: UnsafeRawPointer, count: Int)` - Creates data with copied memory content.
- `init<SourceType>(buffer: UnsafeBufferPointer<SourceType>)` - Creates a data buffer with copied memory content using a buffer pointer.
- `init<SourceType>(buffer: UnsafeMutableBufferPointer<SourceType>)` - Creates a data buffer with copied memory content using a mutable buffer pointer.
- `init(bytesNoCopy: UnsafeMutableRawPointer, count: Int, deallocator: Data.Deallocator)` - Creates a data buffer with memory content without copying the bytes.
- `enum Deallocator` - A deallocator you use to customize how the backing store is deallocated for data created with the no-copy initializer.

### Reading and Writing Data

- `func write(to: URL, options: Data.WritingOptions) throws` - Writes the contents of the data buffer to a location.
- `typealias ReadingOptions` - Options to control the reading of data from a URL.
- `typealias WritingOptions` - Options to control the writing of data to a URL.

### Base-64 Encoding

- `func base64EncodedData(options: Data.Base64EncodingOptions) -> Data` - Returns Base-64 encoded data.
- `func base64EncodedString(options: Data.Base64EncodingOptions) -> String` - Returns a Base-64 encoded string.
- `typealias Base64DecodingOptions` - Options to use when decoding data.
- `typealias Base64EncodingOptions` - Options to use when encoding data.

### Accessing Bytes

- `subscript(Data.Index) -> UInt8` - Accesses the byte at the specified index.

### Accessing Underlying Memory

- `func withUnsafeBytes<ResultType, ContentType>((UnsafePointer<ContentType>) throws -> ResultType) rethrows -> ResultType` - Accesses the raw bytes in the data's buffer.
- `func withUnsafeMutableBytes<ResultType, ContentType>((UnsafeMutablePointer<ContentType>) throws -> ResultType) rethrows -> ResultType` - Mutates the raw bytes in the data's buffer.
- `func copyBytes(to: UnsafeMutablePointer<UInt8>, count: Int)` - Copies the contents of the data to memory.
- `func copyBytes(to: UnsafeMutablePointer<UInt8>, from: Range<Data.Index>)` - Copies a subset of the contents of the data to memory.
- `func copyBytes<DestinationType>(to: UnsafeMutableBufferPointer<DestinationType>, from: Range<Data.Index>?) -> Int` - Copies the bytes in a range from the data into a buffer.

### Adding Bytes

- `func append(Data)` - Appends the specified data to the end of this data.
- `func append<SourceType>(UnsafeBufferPointer<SourceType>)` - Append a buffer of bytes to the data.
- `func append(UnsafePointer<UInt8>, count: Int)` - Appends the specified bytes from memory to the end of the data.
- `func append(contentsOf: [UInt8])` - Appends the bytes in the specified array to the end of the data.

### Replacing a Range of Bytes

- `func replaceSubrange(Range<Data.Index>, with: Data)` - Replaces a region of bytes in the data with new data.
- `func replaceSubrange<ByteCollection>(Range<Data.Index>, with: ByteCollection)` - Replaces a region of bytes in the data with new bytes from a collection.
- `func replaceSubrange<SourceType>(Range<Data.Index>, with: UnsafeBufferPointer<SourceType>)` - Replaces a region of bytes in the data with new bytes from a buffer.
- `func replaceSubrange(Range<Data.Index>, with: UnsafeRawPointer, count: Int)` - Replaces a region of bytes in the data with bytes from memory.

### Finding Bytes

- `func range(of: Data, options: Data.SearchOptions, in: Range<Data.Index>?) -> Range<Data.Index>?` - Finds the range of the specified data as a subsequence of this data, if it exists.
- `typealias SearchOptions` - Options that control a data search operation.

### Excluding Bytes

- `func advanced(by: Int) -> Data` - Returns a new data buffer created by removing the given number of bytes from the front of the original buffer.

### Iterating Over Bytes

- `func makeIterator() -> Data.Iterator` - Returns an iterator over the contents of the data.
- `func enumerateBytes((UnsafeBufferPointer<UInt8>, Data.Index, inout Bool) -> Void)` - Enumerates the contents of the data's buffer.

### Splitting the Buffer

- `func subdata(in: Range<Data.Index>) -> Data` - Returns a new copy of the data in a specified range.

### Comparing Data

- `static func == (Data, Data) -> Bool` - Returns true if the two Data arguments are equal.

### Manipulating Indexes

- `var startIndex: Data.Index` - The beginning index into the data.
- `var endIndex: Data.Index` - The end index into the data.

### Describing Data

- `var description: String` - A human-readable description for the data.
- `var debugDescription: String` - A human-readable debug description for the data.

### Using Reference Types

- `class NSData` - A static byte buffer in memory.
- `class NSMutableData` - An object representing a dynamic byte buffer in memory.

### Initializers

- `init?(base64Encoded: Data, options: Data.Base64DecodingOptions)`
- `init?(base64Encoded: String, options: Data.Base64DecodingOptions)`
- `init(bytes: Array<UInt8>)`
- `init<S>(bytes: S)`
- `init(bytes: ArraySlice<UInt8>)`
- `init(contentsOf: URL, options: Data.ReadingOptions) throws`
- `init(referencing: NSData)`
- `init(repeating: UInt8, count: Int)`

### Instance Properties

- `var bytes: RawSpan`
- `var count: Int`
- `var mutableBytes: MutableRawSpan`
- `var mutableSpan: MutableSpan<UInt8>`
- `var span: Span<UInt8>`

### Instance Methods

- `func hash(into: inout Hasher)` - The hash value for the data.
- `func withUnsafeMutableBytes<ResultType>((UnsafeMutableRawBufferPointer) throws -> ResultType) rethrows -> ResultType`

### Subscripts

- `subscript<R>(R) -> Data`

### Default Implementations

- Attachable Implementations
- CustomDebugStringConvertible Implementations
- CustomStringConvertible Implementations

## Relationships

### Conforms To

- `Attachable`
- `BidirectionalCollection`
- `CKRecordValueProtocol`
- `Collection`
- `ContiguousBytes`
- `Copyable`
- `CustomDebugStringConvertible`
- `CustomReflectable`
- `CustomStringConvertible`
- `DataProtocol`
- `Decodable`
- `Encodable`
- `Equatable`
- `Hashable`
- `MutableCollection`
- `MutableDataProtocol`
- `RandomAccessCollection`
- `RangeReplaceableCollection`
- `ReferenceConvertible`
- `Sendable`
- `SendableMetatype`
- `Sequence`
- `Transferable`