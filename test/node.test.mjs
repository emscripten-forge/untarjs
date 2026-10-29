import { before, describe, it } from 'node:test';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { expect } from 'earl';
import unpack from '../lib/unpack.js';

const wasmPath = fileURLToPath(new URL('../lib/unpack.wasm', import.meta.url));
const streamChunkSize = 256 * 1024;
const condaPackageUrl =
  'https://conda.anaconda.org/conda-forge/linux-64/_libgcc_mutex-0.1-conda_forge.tar.bz2';

const createTar = (name, contents) => {
  const content = Buffer.isBuffer(contents) ? contents : Buffer.from(contents);
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

const extractFiles = (wasmModule, archive) => {
  const inputPointer = wasmModule._malloc(archive.length);
  let resultPointer = 0;

  try {
    new Uint8Array(wasmModule.wasmMemory.buffer).set(archive, inputPointer);
    resultPointer = wasmModule._extract(inputPointer, archive.length, false);

    const status = wasmModule.getValue(resultPointer + 8, 'i32');
    if (status !== 1) {
      throw new Error(wasmModule.UTF8ToString(resultPointer + 12));
    }

    const filesPointer = wasmModule.getValue(resultPointer, 'i32');
    const fileCount = wasmModule.getValue(resultPointer + 4, 'i32');
    const files = {};

    for (let index = 0; index < fileCount; index++) {
      const filePointer = filesPointer + index * 12;
      const filenamePointer = wasmModule.getValue(filePointer, 'i32');
      const dataPointer = wasmModule.getValue(filePointer + 4, 'i32');
      const dataSize = wasmModule.getValue(filePointer + 8, 'i32');
      const filename = wasmModule.UTF8ToString(filenamePointer);
      files[filename] = new Uint8Array(wasmModule.wasmMemory.buffer).slice(
        dataPointer,
        dataPointer + dataSize
      );
    }

    return files;
  } finally {
    if (resultPointer) {
      wasmModule._free_extracted_archive(resultPointer);
    }
    wasmModule._free(inputPointer);
  }
};

const streamArchive = async function* (wasmModule, archive) {
  const inputPointer = wasmModule._malloc(archive.length);
  let streamPointer = 0;
  let chunkPointer = 0;

  try {
    new Uint8Array(wasmModule.wasmMemory.buffer).set(archive, inputPointer);
    streamPointer = wasmModule._archive_stream_open(
      inputPointer,
      archive.length,
      false
    );
    if (!streamPointer) {
      throw new Error('Failed to allocate archive stream');
    }
    chunkPointer = wasmModule._malloc(streamChunkSize);

    const streamError = () =>
      wasmModule.UTF8ToString(wasmModule._archive_stream_error(streamPointer));
    let entryStatus = wasmModule._archive_stream_next_entry(streamPointer);
    while (entryStatus === 1) {
      const path = wasmModule.UTF8ToString(
        wasmModule._archive_stream_entry_path(streamPointer)
      );
      const size = wasmModule._archive_stream_entry_size(streamPointer);
      let offset = 0;
      let bytesRead = wasmModule._archive_stream_read(
        streamPointer,
        chunkPointer,
        streamChunkSize
      );

      if (bytesRead < 0) {
        throw new Error(streamError());
      }
      if (bytesRead === 0) {
        yield { path, size, offset, data: new Uint8Array(0), final: true };
      }

      while (bytesRead > 0) {
        const data = new Uint8Array(
          wasmModule.wasmMemory.buffer,
          chunkPointer,
          bytesRead
        ).slice();
        const nextBytesRead = wasmModule._archive_stream_read(
          streamPointer,
          chunkPointer,
          streamChunkSize
        );

        if (nextBytesRead < 0) {
          yield { path, size, offset, data, final: false };
          throw new Error(streamError());
        }

        yield { path, size, offset, data, final: nextBytesRead === 0 };
        offset += bytesRead;
        bytesRead = nextBytesRead;
      }

      entryStatus = wasmModule._archive_stream_next_entry(streamPointer);
    }

    if (entryStatus < 0) {
      throw new Error(streamError());
    }
  } finally {
    if (streamPointer) {
      wasmModule._archive_stream_close(streamPointer);
    }
    if (chunkPointer) {
      wasmModule._free(chunkPointer);
    }
    wasmModule._free(inputPointer);
  }
};

describe('Node WASM support', () => {
  let wasmModule;
  let wasmBinary;

  before(async () => {
    wasmBinary = await readFile(wasmPath);
    wasmModule = await unpack({ wasmBinary });
  });

  it('loads the WASM file from disk and extracts an archive', () => {
    const archive = createTar('hello.txt', 'Hello from Node');
    const files = extractFiles(wasmModule, archive);

    expect(Object.keys(files)).toEqual(['hello.txt']);
    expect(Buffer.from(files['hello.txt']).toString()).toEqual(
      'Hello from Node'
    );
  });

  it('extracts a large file and grows WASM memory', () => {
    const fileSize = 24 * 1024 * 1024;
    const content = Buffer.alloc(fileSize, 0xa5);
    const archive = createTar('large.bin', content);
    const files = extractFiles(wasmModule, archive);
    const extracted = files['large.bin'];
    const extractedBuffer = Buffer.from(
      extracted.buffer,
      extracted.byteOffset,
      extracted.byteLength
    );

    expect(extracted.length).toEqual(fileSize);
    expect(Buffer.compare(extractedBuffer, content)).toEqual(0);
    expect(wasmModule.wasmMemory.buffer.byteLength > 16 * 1024 * 1024).toEqual(
      true
    );
  });

  it('streams large file contents in bounded chunks', async () => {
    const fileSize = 3 * streamChunkSize + 37;
    const content = Buffer.alloc(fileSize, 0x5a);
    const archive = createTar('streamed.bin', content);
    const chunks = [];

    for await (const chunk of streamArchive(wasmModule, archive)) {
      chunks.push(chunk);
    }

    expect(chunks.length).toEqual(4);
    expect(chunks.map(chunk => chunk.path)).toEqual(
      Array(4).fill('streamed.bin')
    );
    expect(chunks.map(chunk => chunk.offset)).toEqual([
      0,
      streamChunkSize,
      2 * streamChunkSize,
      3 * streamChunkSize
    ]);
    expect(chunks.every(chunk => chunk.data.length <= streamChunkSize)).toEqual(
      true
    );
    expect(chunks.map(chunk => chunk.final)).toEqual([
      false,
      false,
      false,
      true
    ]);
    expect(
      Buffer.compare(
        Buffer.concat(chunks.map(chunk => Buffer.from(chunk.data))),
        content
      )
    ).toEqual(0);
  });

  it('uses less WASM memory when streaming a large file', async () => {
    const fileSize = 32 * 1024 * 1024;
    const content = Buffer.alloc(fileSize, 0x3c);
    const archive = createTar('large-stream.bin', content);
    const materializedModule = await unpack({ wasmBinary });
    const streamingModule = await unpack({ wasmBinary });

    extractFiles(materializedModule, archive);
    const materializedMemory = materializedModule.wasmMemory.buffer.byteLength;
    let streamedSize = 0;
    for await (const chunk of streamArchive(streamingModule, archive)) {
      streamedSize += chunk.data.length;
    }
    const streamingMemory = streamingModule.wasmMemory.buffer.byteLength;

    expect(streamedSize).toEqual(fileSize);
    expect(streamingMemory < materializedMemory).toEqual(true);
  });

  it('extracts the conda package from the README example', async () => {
    const response = await fetch(condaPackageUrl, {
      signal: AbortSignal.timeout(30_000)
    });
    if (!response.ok) {
      throw new Error(
        `Failed to download conda package: HTTP ${response.status}`
      );
    }

    const archive = new Uint8Array(await response.arrayBuffer());
    const files = extractFiles(wasmModule, archive);
    const packageMetadata = JSON.parse(
      new TextDecoder().decode(files['info/index.json'])
    );

    expect(packageMetadata.name).toEqual('_libgcc_mutex');
    expect(packageMetadata.version).toEqual('0.1');
  });
});
