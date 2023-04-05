import { Logger, utils } from '../utilities';
import { AttestationDocument, AttestationRecipient, AttestationIssuer } from './open-attestation.interfaces';
import { IIssuer } from '../configuration/pitstop-config.interface';
import { IParticipant } from '~/utilities/dataDefinitions/HighwayMessage';
import {
  wrapDocument,
  validateSchema,
  signDocument,
  SUPPORTED_SIGNING_ALGORITHM,
  getData,
  WrappedDocument,
  OpenAttestationDocument,
  utils as oaUtils
} from '@govtechsg/open-attestation';
import {
  verify,
  isValid,
  utils as oavUtils,
  ProviderDetails
} from '@govtechsg/oa-verify';
import { attachments } from '../attachments';
import mime from 'mime-types';
import { messageStoreService } from '~/services/messageStoreService';
import _ from 'lodash';
import { pitstopConfig } from '~/configuration/pitstop-config';
import { TitleEscrow__factory, TradeTrustToken__factory } from '@govtechsg/token-registry/contracts';
import { ethers, providers } from 'ethers';
import { ChainId, ChainInfo } from '../tradetrust/chain-infor';
import { getChainInfo } from '../tradetrust/chain-utils';

const logger = new Logger('openAttestation');

export const OPEN_ATTESTATION_FILE_NAME_PREFIX = 'trade_trust_verification_';
export const OPEN_ATTESTATION_FILE_EXTENSION = '.tt';

const ATTACHMENT_REMOVABLE_KEYS = ['encryptionKey', 'url', 'checksum', 'isGeneratedTT', 'key'];

const REVOCATION_TYPE = 'NONE';
const IDENTITY_PROOF_TYPE = 'DNS-DID';
const DID_PREFIX: string = 'did:ethr:';
const DID_SUFFIX: string = '#controller';

type TradeTrustErc721EventType = 'Transfer' | 'Transfer to Wallet' | 'Surrender' | 'Burnt';

interface TitleEscrowEvent extends TradeTrustErc721Event {
  beneficiary: string;
  holderChangeEvents: {
    blockNumber: number;
    holder: string;
    timestamp: number;
  }[];
}
enum EventType {
  TRANSFER = 'Transfer',
  SURRENDER = 'Surrender',
  BURNT = 'Burnt',
  TRANSFER_TO_WALLET = 'Transfer to Wallet'
}
enum ActionType {
  INITIAL = 'Document has been issued',
  ENDORSE = 'Endorse change of ownership',
  TRANSFER = 'Transfer holdership',
  SURRENDERED = 'Document surrendered to issuer',
  SURRENDER_REJECTED = 'Surrender of document rejected',
  SURRENDER_ACCEPTED = 'Surrender of document accepted', // burnt token
  TRANSFER_TO_WALLET = 'Transferred to wallet'
}
export interface HistoryChainInterface {
  action: ActionType;
  isNewBeneficiary: boolean;
  isNewHolder: boolean;
  documentOwner?: string;
  beneficiary?: string;
  holder?: string;
  timestamp?: number;
}
interface VerificationFragmentData {
  did: string;
  location: string;
  status: string;
}
interface TradeTrustErc721Event {
  eventType: TradeTrustErc721EventType;
  documentOwner: string;
  eventTimestamp?: number;
}

export type EndorsementChain = (TradeTrustErc721Event | TitleEscrowEvent)[];

export type WrappedOrSignedOpenAttestationDocument = WrappedDocument<OpenAttestationDocument>;

export class OpenAttestation {
  public async createAttesationDocument(
    issuerDetail: IIssuer,
    recipient: IParticipant,
    payload: any
  ): Promise<AttestationDocument> {
    let attestationDocument = {} as AttestationDocument;
    const attestationRecipient: AttestationRecipient = { name: recipient.name };
    const attestationIssuer: AttestationIssuer = {
      id: DID_PREFIX + issuerDetail.didAddress,
      name: issuerDetail.org.name,
      revocation: { type: REVOCATION_TYPE },
      identityProof: {
        type: IDENTITY_PROOF_TYPE,
        key: DID_PREFIX + issuerDetail.didAddress + DID_SUFFIX,
        location: issuerDetail.org.domain
      }
    };
    attestationDocument.recipient = attestationRecipient;
    attestationDocument.payload = payload;
    attestationDocument.issuers = [];
    attestationDocument.issuers.push(attestationIssuer);
    attestationDocument.attachments =
      payload.attachments && payload.attachments.length > 0
        ? await Promise.all(
            payload.attachments.map(async attachmentObj => {
              return {
                filename: attachmentObj.filename,
                type: mime.contentType(attachmentObj.filename) || 'text/plain',
                data: messageStoreService.isS3Key(attachmentObj.file_content)
                  ? (await attachments.download(attachmentObj.file_content)).toString('base64')
                  : attachmentObj.file_content
              };
            })
          )
        : [];
    return attestationDocument;
  }

  public wrapDocument(wrappingDocument: any): any {
    const wrappedDocument = wrapDocument(wrappingDocument);
    if (validateSchema(wrappedDocument)) {
      return wrappedDocument;
    }
  }

  public async signDocument(wrappedDocument: any, issuerDetail: IIssuer): Promise<any> {
    return signDocument(wrappedDocument, SUPPORTED_SIGNING_ALGORITHM.Secp256k1VerificationKey2018, {
      public: DID_PREFIX + issuerDetail.didAddress + DID_SUFFIX,
      private: issuerDetail.privateKey
    });
  }

  public async verifyDocument(signedDocument: any, payload: any): Promise<boolean> {
    try {
      let unwrappedDocument: any = getData(signedDocument);

      let receivedPayload = JSON.parse(JSON.stringify(payload));

      logger.debug(receivedPayload);

      let payloadAttachments =
        payload.attachments && payload.attachments.length > 0 ? JSON.parse(JSON.stringify(payload.attachments)) : [];

      let unwrappedAttachments =
        unwrappedDocument.attachments && unwrappedDocument.attachments.length > 0
          ? JSON.parse(JSON.stringify(unwrappedDocument.attachments))
          : [];

      //Handling no attachments
      if (!unwrappedDocument.payload.attachments) {
        receivedPayload.attachments = [];
        unwrappedDocument.payload.attachments = [];
      }

      //Remove Generated TT files
      payloadAttachments = payloadAttachments.filter(a => !a.isGeneratedTT);
      receivedPayload.attachments =
        receivedPayload.attachments && receivedPayload.attachments.length > 0
          ? receivedPayload.attachments.filter(a => !a.isGeneratedTT)
          : undefined;

      //Get Base64 of Payload Attachments
      payloadAttachments = await Promise.all(
        payloadAttachments.map(async attachmentObj => {
          return {
            ...attachmentObj,
            data: (await attachments.download(attachmentObj.file_content)).toString('base64'),
            file_content: messageStoreService.isS3Key(attachmentObj.file_content)
              ? attachmentObj.data
              : attachmentObj.file_content
          };
        })
      );
      delete receivedPayload.attachments;
      delete unwrappedDocument.payload.attachments;

      utils.removePropsInJSON(receivedPayload, ATTACHMENT_REMOVABLE_KEYS);
      utils.removePropsInJSON(unwrappedDocument, ATTACHMENT_REMOVABLE_KEYS);

      let attachmentsMismatched = [];
      if (payloadAttachments.length > 0 && unwrappedAttachments.length > 0) {
        attachmentsMismatched = _.differenceBy(payloadAttachments, unwrappedAttachments, 'data');
      }

      return (
        unwrappedDocument &&
        unwrappedDocument.payload &&
        isValid(await verify(signedDocument)) &&
        _.isEqual(unwrappedDocument.payload, receivedPayload) &&
        attachmentsMismatched.length === 0
      );
    } catch (err) {
      logger.error(err);
      return false;
    }
  }

  public getIssuerDetail(signedDocument: any) {
    let unwrappedDocument: any = getData(signedDocument);
    return (unwrappedDocument && unwrappedDocument.issuers) || [];
  }

  public isOpenAttestationFile = (decodedData: string) => {
    try {
      const decodedJson = JSON.parse(decodedData);
      const unwrappedDocument = oaUtils.getDocumentData(decodedJson);
      if (!unwrappedDocument) throw new Error("File is not OA document"); //non-OA document returns undefined
      return true;
    } catch (e) {
      return false;
    }
  };

  public async validateAllSGTradexTTAttachments(ttAttachments: any): Promise<boolean> {
    let isAllSGTradexTT: boolean = true;
    for (let ttAttachment of ttAttachments) {
      const ttAttachmentBuffer = await attachments.download(ttAttachment.file_content);
      const ttDocument = JSON.parse(ttAttachmentBuffer.toString('utf-8'));
      const issuers = this.getIssuerDetail(ttDocument);
      const sgtradexIssuers = (await pitstopConfig.getOrgSysData())?.orgs;
      const isIssuerFound = issuers.some(i => sgtradexIssuers.findIndex(si => si.didAddress === i.id) > -1);
      if (!isIssuerFound) {
        isAllSGTradexTT = false;
        break;
      }
    }
    return isAllSGTradexTT;
  }

  public getTokenId(document) {
    if (oaUtils.isTransferableAsset(document)) {
      try {
        return `0x${oaUtils.getAssetId(document)}`;
      } catch (e) {
        logger.error(e)
      }
    }
    return 'unable to getTokenId';
  }

  public getTokenRegistryAddress(document) {
    const getAddress = (document: WrappedOrSignedOpenAttestationDocument): string | undefined => {
      const issuerAddress = oaUtils.getIssuerAddress(document);
      return issuerAddress instanceof Array ? issuerAddress[0] : issuerAddress;
    };
    return oaUtils.isTransferableAsset(document) ? getAddress(document) : '';
  }

  public getTokenRegistry(tokenRegistryAddress, providerOrSigner) {
    const instance = TradeTrustToken__factory.connect(tokenRegistryAddress, providerOrSigner);
    return instance;
  }

  public fetchEventInfo = async (
    address: string,
    blockNumber: number,
    eventType: TradeTrustErc721EventType,
    provider: providers.Provider
  ): Promise<TradeTrustErc721Event> => {
    const eventTimestamp = (await (await provider.getBlock(blockNumber)).timestamp) * 1000;
    return {
      eventType,
      documentOwner: address,
      eventTimestamp
    };
  };

  public fetchEvents = async (
    address: string,
    blockNumber: number,
    provider: providers.Provider
  ): Promise<TradeTrustErc721Event> => {
    const code = await provider.getCode(address);
    const isContractDeployed = code === '0x';
    if (isContractDeployed) {
      return await this.fetchEventInfo(address, blockNumber, 'Transfer to Wallet', provider);
    } else {
      return await this.fetchEscrowTransfers(address, provider);
    }
  };

  public fetchEscrowTransfers = async (address: string, provider: providers.Provider): Promise<TitleEscrowEvent> => {
    const titleEscrowContract = TitleEscrow__factory.connect(address, provider);
    const isTitleEscrow = await titleEscrowContract.supportsInterface('0xdcce2211');
    if (!isTitleEscrow) throw new Error(`Contract ${address} is not a title escrow contract`);
    const holderChangeFilter = titleEscrowContract.filters.HolderTransfer(null, null);
    // const holderChangeFilter = titleEscrowContract.filters.HolderChanged(null, null);
    const holderChangeLogsDeferred = provider.getLogs({ ...holderChangeFilter, fromBlock: 0 });

    const beneficiaryDeferred = titleEscrowContract.beneficiary();
    const [beneficiary, holderChangeLogs] = await Promise.all([beneficiaryDeferred, holderChangeLogsDeferred]);
    const holderChangeLogsParsed = holderChangeLogs.map(log => {
      if (!log.blockNumber) throw new Error('Block number not present');
      return {
        ...log,
        ...titleEscrowContract.interface.parseLog(log)
      };
    });
    holderChangeLogsParsed.forEach(e => {
      if (!e.blockNumber) throw new Error('');
    });
    const blockTimes = await Promise.all(
      holderChangeLogsParsed.map(async event => {
        return (await (await provider.getBlock(event.blockNumber)).timestamp) * 1000;
      })
    );
    return {
      eventType: 'Transfer',
      documentOwner: address,
      beneficiary,
      holderChangeEvents: holderChangeLogsParsed.map((event, index) => ({
        blockNumber: event.blockNumber,
        holder: event.args.newHolder as string,
        timestamp: blockTimes[index]
      }))
    };
  };

  public async fetchEndorsementChain(tokenRegistryAddress, tokenId, provider, providerOrSigner, document): Promise<EndorsementChain | undefined> {
    const tokenRegistry = this.getTokenRegistry(this.getTokenRegistryAddress(document), providerOrSigner);
    if (!tokenRegistry || !provider || !providerOrSigner) return;
    try {
      // Fetch transfer logs from token registry
      const transferLogFilter = tokenRegistry.filters.Transfer(null, null, tokenId);
      const logs = await tokenRegistry.queryFilter(transferLogFilter, 0);
      const formattedLogs = logs.map(log => {
        const { blockNumber, args: values, transactionHash } = log;
        if (!values) throw new Error(`Transfer log malformed: ${log}`);
        return {
          blockNumber,
          transactionHash,
          from: values['from'] as string,
          to: values['to'] as string
        };
      });
      const titleEscrowLogs: TradeTrustErc721Event[] = await Promise.all(
        formattedLogs.map(log => {
          switch (log.to) {
            case tokenRegistryAddress:
              return this.fetchEventInfo(log.to, log.blockNumber, 'Surrender', provider);
            case '0x000000000000000000000000000000000000dEaD':
              return this.fetchEventInfo(log.to, log.blockNumber, 'Burnt', provider);
            default:
              return this.fetchEvents(log.to, log.blockNumber, provider);
          }
        })
      );

      return titleEscrowLogs;
    } catch (e) {
      if (e instanceof Error) {
        console.error('titleEscrowLogs error', e);
      }
    }
  }

  public async getHistoryChain(document, provider, providerOrSigner) {
    const historyChain: HistoryChainInterface[] = [
      {
        action: ActionType.INITIAL,
        isNewBeneficiary: true,
        isNewHolder: false
      }
    ];

    let previousBeneficiary = '';
    let previousHolder = '';
    const getEndorsementChainData = await this.fetchEndorsementChain(
      this.getTokenRegistryAddress(document),
      this.getTokenId(document),
      provider,
      providerOrSigner,
      document
    );
    getEndorsementChainData?.forEach(endorsementChainEvent => {
      const chain = endorsementChainEvent as TitleEscrowEvent;
      const documentOwner = chain.documentOwner;
      const beneficiary = chain.beneficiary;
      const chainEventTimestamp = chain.eventTimestamp;

      switch (chain.eventType) {
        case EventType.TRANSFER:
          chain.holderChangeEvents.forEach(holderEvent => {
            const holder = holderEvent.holder;
            const holderEventTimestamp = holderEvent.timestamp;
            const isNewBeneficiary = beneficiary !== previousBeneficiary;
            const isNewHolder = holder !== previousHolder;

            if (previousBeneficiary === beneficiary && previousHolder === holder) {
              historyChain.push({
                action: ActionType.SURRENDER_REJECTED,
                isNewBeneficiary,
                isNewHolder,
                documentOwner,
                beneficiary,
                holder,
                timestamp: holderEventTimestamp
              });
            } else if (previousBeneficiary != beneficiary) {
              historyChain.push({
                action: ActionType.ENDORSE,
                isNewBeneficiary,
                isNewHolder,
                documentOwner,
                beneficiary,
                holder,
                timestamp: holderEventTimestamp
              });
            } else if (previousHolder !== holder) {
              historyChain.push({
                action: ActionType.TRANSFER,
                isNewBeneficiary,
                isNewHolder,
                documentOwner,
                beneficiary,
                holder,
                timestamp: holderEventTimestamp
              });
            }

            previousHolder = holder;
            previousBeneficiary = beneficiary;
          });
          break;
        case EventType.SURRENDER:
          historyChain.push({
            action: ActionType.SURRENDERED,
            isNewBeneficiary: true,
            isNewHolder: false,
            timestamp: chainEventTimestamp
          });
          // not reassigning previousBeneficiary and previousHolder so that it takes the addresses from the point just before it was surrendered
          break;
        case EventType.BURNT:
          historyChain.push({
            action: ActionType.SURRENDER_ACCEPTED,
            isNewBeneficiary: true,
            isNewHolder: false,
            timestamp: chainEventTimestamp
          });
          previousHolder = '';
          previousBeneficiary = '';
          break;
        case EventType.TRANSFER_TO_WALLET:
          historyChain.push({
            action: ActionType.TRANSFER_TO_WALLET,
            isNewBeneficiary: true,
            isNewHolder: false,
            timestamp: chainEventTimestamp,
            documentOwner,
            beneficiary
          });
          previousHolder = '';
          previousBeneficiary = beneficiary;
          break;
        default:
          throw Error('eventType not matched');
      }
    });
    return historyChain;
  }

  public async getTitleEscrowAddress(tokenRegistryAddress, document, chainId) {
    const titleEscrowAddress = await this.getTokenRegistry(tokenRegistryAddress, this.getProviderDetails(chainId)).ownerOf(
      this.getTokenId(document)
    );    
    return titleEscrowAddress;
  }

  public async getTitleEscrow(tokenRegistryAddress, document, chainId) {
    const titleEscrowAddress = await this.getTitleEscrowAddress(tokenRegistryAddress, document, chainId);
    const instance = TitleEscrow__factory.connect(titleEscrowAddress, this.getProviderDetails(chainId));
    return instance;
  }

  public getProviderDetails(chainId: ChainId) {
    const createProvider = (chainId: ChainId) => {
      const url = ChainInfo[chainId].rpcUrl;
      const opts: ProviderDetails = url
        ? { url }
        : {
            network: getChainInfo(chainId).networkName,
            providerType: 'infura',
            apiKey: process.env.INFURA_API_KEY || 'bb46da3f80e040e8ab73c0a9ff365d18'
          };
      return chainId === ChainId.Local ? new providers.JsonRpcProvider() : oavUtils.generateProvider(opts);
    };
    let currentProvider: providers.Provider = createProvider(chainId);

    return currentProvider;
  }

  public getSignerDetails(chainId: ChainId) {
    let signer;
    try {
      signer = (this.getProviderDetails(chainId) as ethers.providers.Web3Provider).getSigner();
    } catch (e) {
      logger.error('Signer error',e)
    }
    return signer;
  }

  public validateNominateBeneficiary = async (beneficiaryNominee,titleEscrow): Promise<void> => {
    const beneficiary = await titleEscrow.beneficiary();
    if (beneficiaryNominee === beneficiary) {
      const error = "new beneficiary address is the same as the current beneficiary address";
      console.log("error",error);
      throw new Error(error);
    }
  };

 
}

export const openAttestation = new OpenAttestation();
