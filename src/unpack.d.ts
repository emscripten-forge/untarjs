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
  getValue(ptr: number, type: string): number;
}

declare const unpack: {
  (options: { locateFile: (path: string) => string }): Promise<IWasmModule>;
};

export default unpack;
