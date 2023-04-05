
export type AttestationDocument = {
    recipient: AttestationRecipient,
    //  $template?: AttestationTemplate | undefined,
    issuers: AttestationIssuer[],
    payload: any,
    attachments: any
}

export type AttestationRecipient = {
    name: string | undefined
}

export type AttestationTemplate = {
    name: string,
    type: "EMBEDDED_RENDERER",
    url?: string
}
export type AttestationIssuer = {
    id: string,
    name: string,
    revocation: AttestationIssuerRevocation,
    identityProof: AttestationIssuerIdentityProof
}

export type AttestationIssuerRevocation = {
    type: 'NONE'
}

export type AttestationIssuerIdentityProof = {
    type: "DNS-DID",
    location?: string,
    key: string
}