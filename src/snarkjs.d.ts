// Minimal typings for snarkjs 0.7.x (ships no TypeScript declarations).
declare module "snarkjs" {
  export namespace groth16 {
    function fullProve(
      input: Record<string, string>,
      wasmFile: string,
      zkeyFile: string,
    ): Promise<{ proof: unknown; publicSignals: string[] }>;
    function verify(
      vk: unknown,
      publicSignals: string[],
      proof: unknown,
    ): Promise<boolean>;
  }
  export namespace wtns {
    function calculate(
      input: Record<string, unknown>,
      wasmFile: string,
    ): Promise<Uint8Array>;
  }
}
