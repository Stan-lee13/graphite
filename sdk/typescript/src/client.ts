import type { VerificationInput, VerificationResult, ProtocolManifest } from "./types.js";

export interface GraphiteClientOptions {
  baseUrl: string;
}

export class GraphiteClient {
  private baseUrl: string;

  constructor(options: GraphiteClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
  }

  async verify(input: VerificationInput): Promise<VerificationResult> {
    const response = await fetch(`${this.baseUrl}/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(input),
    });

    if (!response.ok) {
      const errorBody = await response.json().catch(() => ({}));
      throw new Error(
        `Graphite verification failed: ${response.status} ${response.statusText} — ${errorBody.error ?? ""}`
      );
    }

    return (await response.json()) as VerificationResult;
  }

  async health(): Promise<{ status: string; service: string; version: string }> {
    const response = await fetch(`${this.baseUrl}/health`);
    if (!response.ok) throw new Error(`Health check failed: ${response.status}`);
    return await response.json();
  }

  async listManifests(): Promise<ProtocolManifest[]> {
    const response = await fetch(`${this.baseUrl}/manifests`);
    if (!response.ok) throw new Error(`Failed to list manifests: ${response.status}`);
    return await response.json();
  }
}
