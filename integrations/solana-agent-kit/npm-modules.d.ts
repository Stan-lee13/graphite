// Type declarations for npm packages that are installed at runtime via npm install.
// These are only needed for static type-checking in environments without node_modules.
// In production, the real type declarations from the installed packages are used.

declare module "solana-agent-kit" {
  export class SolanaAgentKit {
    constructor(wallet: unknown, rpcUrl: string, config: Record<string, string>);
    use(plugin: unknown): this;
    methods: Record<string, (...args: unknown[]) => Promise<unknown>>;
  }
  export class KeypairWallet {
    constructor(keypair: unknown);
  }
}

declare module "@solana-agent-kit/plugin-token" {
  const plugin: unknown;
  export default plugin;
}

declare module "@solana-agent-kit/plugin-defi" {
  const plugin: unknown;
  export default plugin;
}

declare module "@solana/web3.js" {
  export class Keypair {
    static fromSecretKey(secretKey: Uint8Array): Keypair;
  }
}

declare module "bs58" {
  function decode(str: string): Uint8Array;
  export default decode;
}
