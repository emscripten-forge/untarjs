import { describe, it } from 'node:test';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { expect } from 'earl';
import unpack from '../lib/unpack.js';

const wasmPath = fileURLToPath(new URL('../lib/unpack.wasm', import.meta.url));

const createTar = (name, contents) => {
  const content = Buffer.from(contents);
  const header = Buffer.alloc(512);
  header.write(name, 0, 100, 'utf8');
  header.write('0000644\0', 100, 8, 'ascii');
  header.write('0000000\0', 108, 8, 'ascii');
  header.write('0000000\0', 116, 8, 'ascii');
  header.write(
    `${content.length.toString(8).padStart(11, '0')}\0`,
    124,
    12,
    'ascii'
  );
  header.write('00000000000\0', 136, 12, 'ascii');
  header.fill(0x20, 148, 156);
  header.write('0', 156, 1, 'ascii');
  header.write('ustar\0', 257, 6, 'ascii');
  header.write('00', 263, 2, 'ascii');

  const checksum = header.reduce((sum, byte) => sum + byte, 0);
  header.write(`${checksum.toString(8).padStart(6, '0')}\0 `, 148, 8, 'ascii');

  const paddedContent = Buffer.alloc(Math.ceil(content.length / 512) * 512);
  content.copy(paddedContent);
  return Buffer.concat([header, paddedContent, Buffer.alloc(1024)]);
};

describe('Node WASM support', () => {
  it('loads the WASM file from disk and extracts an archive', async () => {
    const wasmModule = await unpack({
      wasmBinary: await readFile(wasmPath)
    });
    const archive = createTar('hello.txt', 'Hello from Node');
    const inputPointer = wasmModule._malloc(archive.length);
    let resultPointer = 0;

    try {
      wasmModule.HEAPU8.set(archive, inputPointer);
      resultPointer = wasmModule._extract(inputPointer, archive.length, false);

      expect(wasmModule.getValue(resultPointer + 8, 'i32')).toEqual(1);
      expect(wasmModule.getValue(resultPointer + 4, 'i32')).toEqual(1);

      const filesPointer = wasmModule.getValue(resultPointer, 'i32');
      const filenamePointer = wasmModule.getValue(filesPointer, 'i32');
      const dataPointer = wasmModule.getValue(filesPointer + 4, 'i32');
      const dataSize = wasmModule.getValue(filesPointer + 8, 'i32');

      expect(wasmModule.UTF8ToString(filenamePointer)).toEqual('hello.txt');
      expect(
        Buffer.from(wasmModule.HEAPU8.buffer, dataPointer, dataSize).toString()
      ).toEqual('Hello from Node');
    } finally {
      if (resultPointer) {
        wasmModule._free_extracted_archive(resultPointer);
      }
      wasmModule._free(inputPointer);
    }
  });
});
