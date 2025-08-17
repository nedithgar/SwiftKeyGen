# init(first:next:)

**Initializer**

> Initializes every element in this array, by calling the given closure with each preceding element.

**Availability:**
* iOS 26.0+
* iPadOS 26.0+
* Mac Catalyst 26.0+
* macOS 26.0+
* tvOS 26.0+
* visionOS 26.0+
* watchOS 26.0+

```swift
init<E>( first: consuming Element, next: (borrowing Element) throws(E) -> Element ) throws(E) where E : Error
```

The first value to emplace into the array.

