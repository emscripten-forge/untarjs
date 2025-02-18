import unpack, { IWasmModule } from './unpack';
import unpackWasm from './unpack.wasm';

const initializeWasm = async (): Promise<IWasmModule> => {
  const wasmModule: IWasmModule = await unpack({
    locateFile(path: string) {
      if (path.endsWith('.wasm')) {
        return (new URL(unpackWasm, import.meta.url)).href;
      }
      return path;
    }
  });

  return wasmModule;
};

export default initializeWasm;
