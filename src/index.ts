import "dotenv/config";
import express, { Request, Response } from "express";
import axios from "axios";
import {
  SchemaEncoder,
  ZERO_BYTES32,
  NO_EXPIRATION,
} from "@ethereum-attestation-service/eas-sdk";
import { EIP712Proxy } from "@ethereum-attestation-service/eas-sdk/dist/eip712-proxy.js";
import { Wallet, JsonRpcProvider } from "ethers";
import cors from "cors";

const app = express();
app.use(cors());

if (!process.env.SCROLL_EAS_SCAN_URL) {
  console.error("Missing SCROLL_EAS_SCAN_URL environment variable");
}
if (!process.env.SCROLL_BADGE_ATTESTATION_SIGNER_PRIVATE_KEY) {
  console.error(
    "Missing SCROLL_BADGE_ATTESTATION_SIGNER_PRIVATE_KEY environment variable"
  );
}
if (!process.env.PASSPORT_SCORE_ATTESTER_CONTRACT_ADDRESS) {
  console.error(
    "Missing PASSPORT_SCORE_ATTESTER_CONTRACT_ADDRESS environment variable"
  );
}
if (!process.env.PASSPORT_SCORE_SCHEMA_UID) {
  console.error("Missing PASSPORT_SCORE_SCHEMA_UID environment variable");
}
if (!process.env.SCROLL_RPC_URL) {
  console.error("Missing SCROLL_RPC_URL environment variable");
}
if (!process.env.ATTESTER_PROXY_ADDRESS) {
  console.error("Missing ATTESTER_PROXY_ADDRESS environment variable");
}
if (!process.env.SCROLL_BADGE_SCHEMA_UID) {
  console.error("Missing SCROLL_BADGE_SCHEMA_UID environment variable");
}

const SCROLL_EAS_SCAN_URL: string = `${process.env.SCROLL_EAS_SCAN_URL}`;
const ATTESTATION_SIGNER_PRIVATE_KEY: string = `${process.env.SCROLL_BADGE_ATTESTATION_SIGNER_PRIVATE_KEY}`;
const PASSPORT_SCORE_ATTESTER_CONTRACT_ADDRESS: string = `${process.env.PASSPORT_SCORE_ATTESTER_CONTRACT_ADDRESS}`;
const PASSPORT_SCORE_SCHEMA_UID: string = `${process.env.PASSPORT_SCORE_SCHEMA_UID}`;
const SCROLL_BADGE_SCHEMA_UID: string = `${process.env.SCROLL_BADGE_SCHEMA_UID}`;

const SCROLL_RPC_URL: string = `${process.env.SCROLL_RPC_URL}`;
const ATTESTER_PROXY_ADDRESS: string = `${process.env.ATTESTER_PROXY_ADDRESS}`;
// default port to listen on
const port = process.env.SERVICE_PORT || 80;

const SCROLL_BADGE_SCHEMA = "address badge, bytes payload";

export type Attestation = {
  recipient: string;
  revocationTime: number;
  revoked: boolean;
  expirationTime: number;
  decodedDataJson: string;
  schema: {
    id: string;
  };
};

export type EASQueryResponse = {
  data?: {
    data?: {
      attestations: Attestation[];
    };
  };
};

type ScoreAttestation = {
  name: string;
  type: string;
  signature: string;
  value: {
    name: string;
    type: string;
    value: {
      type: string;
      hex: string;
    };
  };
};

// Based on https://axios-http.com/docs/handling_errors
export const handleAxiosError = <T extends Error>(
  error: any,
  label: string,
  // Accept any child class of Error
  ErrorClass: new (...args: any[]) => T,
  secretsToHide?: string[]
) => {
  if (axios.isAxiosError(error)) {
    let message = `Error making ${label} request, `;
    if (error.response) {
      // Received a non 2xx response
      const { data, status, headers } = error.response;
      message += `received error response with code ${status}: ${JSON.stringify(
        data
      )}, headers: ${JSON.stringify(headers)}`;
    } else if (error.request) {
      // No response received
      message += "no response received, " + error.message;
    } else {
      // Something happened in setting up the request that triggered an Error
      message += error.message;
    }
    secretsToHide?.forEach((secret) => {
      message = message.replace(secret, "[SECRET]");
    });
    throw new ErrorClass(message);
  }
  throw error;
};

class ProviderVerificationError extends Error {
  constructor(message: string) {
    super(message);
    if (this.constructor === ProviderVerificationError) {
      throw new Error(
        "ProviderVerificationError is an abstract class and cannot be instantiated directly."
      );
    }
    this.name = this.constructor.name;
  }
}

export class ProviderExternalVerificationError extends ProviderVerificationError {
  constructor(message: string) {
    super(message);
  }
}

const provider = new JsonRpcProvider(SCROLL_RPC_URL);
const signer = new Wallet(ATTESTATION_SIGNER_PRIVATE_KEY, provider);

export const handleProviderAxiosError = (
  error: any,
  label: string,
  secretsToHide?: string[]
) => {
  return handleAxiosError(
    error,
    label,
    ProviderExternalVerificationError,
    secretsToHide
  );
};

export const getAttestations = async (
  address: string,
  attester: string,
  easScanUrl: string
): Promise<Attestation[]> => {
  const query = `
    query {
      attestations(
        where: {
          attester: {
            equals: "${attester}"
            mode: insensitive
          }
          recipient: {
            equals: "${address}"
            mode: insensitive
          }
          schemaId: {
            equals: "${PASSPORT_SCORE_SCHEMA_UID}"
            mode: insensitive
          }
        }
        orderBy: [{ timeCreated: desc }]
      ) {
          recipient
          revocationTime
          revoked
          expirationTime
          decodedDataJson
          schema {
            id
          }
        }      
    }
`;

  let result: EASQueryResponse | undefined = undefined;
  try {
    result = await axios.post(easScanUrl, {
      query,
    });
  } catch (e) {
    handleProviderAxiosError(e, "EAS attestation", []);
  }

  return result?.data?.data?.attestations || [];
};

export function parseScoreFromAttestation(
  attestations: Attestation[]
): number | null {
  const schemaId = PASSPORT_SCORE_SCHEMA_UID;
  const validAttestation = attestations.find(
    (attestation) =>
      attestation.revoked === false &&
      attestation.revocationTime === 0 &&
      attestation.expirationTime === 0 &&
      attestation.schema.id === schemaId
  );

  if (!validAttestation) {
    return null;
  }

  try {
    const decodedData = JSON.parse(
      validAttestation.decodedDataJson
    ) as ScoreAttestation[];
    const scoreData = decodedData.find((item) => item.name === "score");
    const scoreDecimalsData = decodedData.find(
      (item) => item.name === "score_decimals"
    );

    if (scoreData?.value?.value?.hex && scoreDecimalsData?.value?.value) {
      const score = Number(BigInt(scoreData.value.value.hex));
      const decimals = Number(scoreDecimalsData.value.value);
      return Number(score) / 10 ** decimals;
    }
  } catch (error) {
    console.error("Error parsing score from attestation:", error);
  }

  return null;
}

// return a JSON error response with a 400 status
const errorRes = (
  res: Response,
  error: string | object,
  errorCode: number
): Response => res.status(errorCode).json({ error });

app.get("/scroll", (req: Request, res: Response) => {
  res.send("Hello, world!");
});

app.get("/scroll/health", (req: Request, res: Response) => {
  res.status(200).json({ status: "Healthy" });
});

app.get("/health", (req: Request, res: Response) => {
  res.status(200).json({ status: "Healthy" });
});

app.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});

const check = async (req: Request, res: Response) => {
  const { badge, recipient } = req.query;

  if (
    !badge ||
    !recipient ||
    typeof recipient !== "string" ||
    typeof badge !== "string"
  ) {
    return void errorRes(res, "Missing badge or recipient parameter", 400);
  }

  try {
    const attestations = await getAttestations(
      recipient,
      PASSPORT_SCORE_ATTESTER_CONTRACT_ADDRESS,
      SCROLL_EAS_SCAN_URL
    );
    const score = parseScoreFromAttestation(attestations);

    const eligibility = Boolean(score && score >= 20);
    return void res.json({
      code: eligibility ? 1 : 0,
      message: eligibility
        ? "success"
        : `${recipient} does not have an attestation with a score above 20`,
      eligibility,
    });
  } catch (error) {
    console.error("Error verifying attestation:", error);
    return void errorRes(res, "Error verifying attestation", 500);
  }
};

// Check Eligibility For Minting Badge
app.get("/scroll/check", check);
app.get("/check", check);

const claim = async (req: Request, res: Response): Promise<void> => {
  // See example implementation here: https://github.com/scroll-tech/canvas-contracts/blob/master/examples/src/attest-server.js
  const { badge, recipient } = req.query;

  if (!recipient || typeof recipient !== "string")
    return void res.json({
      code: 0,
      message: "missing query parameter 'recipient'",
    });
  if (!badge || typeof badge !== "string")
    return void res.json({ code: 0, message: "missing parameter 'badge'" });

  const attestations = await getAttestations(
    recipient,
    PASSPORT_SCORE_ATTESTER_CONTRACT_ADDRESS,
    SCROLL_EAS_SCAN_URL
  );
  const score = parseScoreFromAttestation(attestations);

  const eligibility = score && score >= 20;
  if (!eligibility)
    return void res.json({ eligibility, code: 0, message: "not eligible" });
  if (typeof badge !== "string")
    return void res.json({
      eligibility,
      code: 0,
      message: "invalid parameter 'badge'",
    });

  try {
    const proxy = new EIP712Proxy(ATTESTER_PROXY_ADDRESS);

    const encoder = new SchemaEncoder(SCROLL_BADGE_SCHEMA);
    const data = encoder.encodeData([
      { name: "badge", value: badge, type: "address" },
      { name: "payload", value: "0x", type: "bytes" },
    ]);

    console.log("encoded data: ", data);

    const currentTime = Math.floor(new Date().getTime() / 1000);
    const deadline = currentTime + 3600;

    const delegatedProxy = await proxy.connect(signer).getDelegated();
    const attestation = {
      // attestation data
      schema: SCROLL_BADGE_SCHEMA_UID,
      recipient,
      data,

      // unused fields
      revocable: true,
      refUID: ZERO_BYTES32,
      value: BigInt(0),
      expirationTime: NO_EXPIRATION,

      // signature details
      deadline: BigInt(deadline),
      attester: signer.address,
    };

    console.log("Signing attestation...");
    const signature = await delegatedProxy.signDelegatedProxyAttestation(
      attestation,
      signer
    );

    console.log("signature", signature);
    // claimer vs attester
    const attestByDelegationInput = {
      schema: attestation.schema,
      data: attestation,
      attester: attestation.attester,
      signature: signature.signature,
      deadline: attestation.deadline,
    };

    console.log("Populating transaction...");
    const tx = await proxy.contract.attestByDelegation.populateTransaction(
      attestByDelegationInput
    );

    console.log("tx", tx);
    return void res.json({ code: 1, message: "success", tx });
  } catch (e) {
    console.error("Error claiming badge:", e);
    return void res.json({ code: 0, message: String(e) });
  }
};

// Claim Badge
app.get("/scroll/claim", claim);
app.get("/claim", claim);
