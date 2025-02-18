import unpack, { IWasmModule } from './unpack';
import unpackWasm from './unpack.wasm';

const initializeWasm = async (locateWasm?: (file: string) => string): Promise<IWasmModule> => {
  const wasmModule: IWasmModule = await unpack({
    locateFile(path: string) {
      if (path.endsWith('.wasm')) {
        if (locateWasm) {
          return locateWasm(path);
        }
        return unpackWasm;
      }
      return path;
    }
  });

  return wasmModule;
};

export default initializeWasm;
