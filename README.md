## Untarjs

Fetching and unpacking archives. This package uses compiled `libarchive` into wasm and supports: tar, bzip2, zstd, zlib, zip, ustar, pax, v7, gnutar, cpio, mtree.

> Note: To add the support of another archive format,  `libarchive` should be compiled again with `--with-[name-archive-lib]` into wasm here [Libarchive recipe](https://github.com/emscripten-forge/recipes/blob/main/recipes/recipes_emscripten/libarchive/build.sh#L11) and then run `yarn run build` in this project to make new unpack.js and unpack.wasm files.

## Using

This package has 2 methods:
- extract(url) - downloads an archive through the url and returns extracted data as an object representing the file structure:
```
{
    "file1": Uint8Array
    "info/paths.json":  Uint8Array,
    ...
}
```
- exctractData(data) - accepts Uint8Array archive data and returns exracted data in the same format which `extract` method does.

The example of using:
```sh
import { initUntarJS } from "@emscripten-forge/untarjs";

const untarjs = await initUntarJS();

const condaPackageUrl = 'https://conda.anaconda.org/conda-forge/linux-64/_libgcc_mutex-0.1-conda_forge.tar.bz2';
untarjs.extract(condaPackageUrl).then((files)=>{
    console.log(files);
});
```
> Note: If this package is used in the project where Webpack is used then webpack.config should include next:
> ```
> resolve: {
>    fallback: {
>      "path": require.resolve("path-browserify"),
>      "crypto": require.resolve("crypto-browserify"),
>      "stream": require.resolve("stream-browserify"),
>      "buffer": require.resolve("buffer/"),
>      "process": require.resolve("process/browser"),
>      "assert": require.resolve("assert/"),
>      "http": require.resolve("stream-http"),
>      "https": require.resolve("https-browserify"),
>      "os": require.resolve("os-browserify/browser"),
>      "url": require.resolve("url/"),
>      "fs": require.resolve("browserify-fs"),
>      "vm": require.resolve("vm-browserify")
>    }
>  },
> ```
