# Protod3

This is a fork of [sysdream/Protod](https://github.com/sysdream/Protod). Credits to the creators of Protod.

This code has successfully been used to extract `.proto` files from a binary that used the proto2 syntax.

However, **it is untested on proto3**.

---

> Protod - Protobuf's metadata extractor
>
> (c) 2012, Sysdream (d.cauquil@sysdream.com)

---

Changes:

-   Adapted to Python 3.10
-   Code has been refactored to (hopefully) make it easier to understand
-   New functionality that improves execution time, in my case by ~50x

    -   _NEW_: Specify pattern to search for (instead of `b'.proto'`, you might choose `b'.proto\x12'`.
        In my case, this avoided many "false positives")
    -   _NEW_: Ignore certain filenames by passing a filename predicate to the `ProtobufExtractor`. For instance:

    ```python
    def filename_predicate(filename: str):
        return "google/protobuf" not in filename

        [...]
        extractor = ProtobufExtractor(sys.argv[1], filename_predicate=filename_predicate)
        extractor.extract(byte_pattern=b".proto\x12")
    ```

## Usage

To extract every `.proto` file from a given executable:

```
python src/protod.py somebinary
```

### Configuration

-   To change what filenames are included, modify the `filename_predicate` function in `src/protod3.py`.
-   To change the `byte_pattern` (most permissive to catch all proto files: `b'.proto'`), edit the `byte_pattern` parameter
    that is passed to `ProtobufExtractor::extract`. `b'.proto\x12'` worked well for my use case.

## What is Protod ?

Protod is a tool able to extract Google's protobuf metadata from any binary
file. This version has been designed to cover every file format.

The goal of this tool is to recover serialized protobuf's metadata inserted
at compilation time inside an executable, and to make it available as .proto
file, ready to compile with protoc (protobuf's compiler).

For further information on Google's protobuf library, please see:

https://developers.google.com/protocol-buffers/docs/overview
