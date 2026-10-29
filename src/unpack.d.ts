export interface IWasmModule {
  wasmMemory: WebAssembly.Memory;
  _free_extracted_archive(resultPtr: number): void;
  UTF8ToString(filenamePtr: number): string;
  _malloc(size: number): number;
  _free(ptr: number): void;
  _extract(
    inputPtr: number,
    inputSize: number,
    decompressionOnly: boolean
  ): number;
  _archive_stream_open(inputPtr: number, inputSize: number, raw: boolean): number;
  _archive_stream_next_entry(streamPtr: number): number;
  _archive_stream_entry_path(streamPtr: number): number;
  _archive_stream_entry_size(streamPtr: number): number;
  _archive_stream_read(streamPtr: number, outputPtr: number, outputSize: number): number;
  _archive_stream_error(streamPtr: number): number;
  _archive_stream_close(streamPtr: number): void;
  getValue(ptr: number, type: string): number;
}

declare const unpack: {
  (options: { locateFile: (path: string) => string }): Promise<IWasmModule>;
};

export default unpack;
