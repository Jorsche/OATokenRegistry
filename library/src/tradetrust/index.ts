import { getData } from '@govtechsg/open-attestation';
import { openAttestation } from '~/open-attestation';
import { ChainId, ChainInfo, ChainInfoObject } from './chain-infor';
import { UnsupportedNetworkError } from './error';
import { isValid, openAttestationDidIdentityProof, openAttestationVerifiers, verificationBuilder } from "@govtechsg/oa-verify";
import { Logger } from '../utilities';

import prettyBytes from 'pretty-bytes';
import atob from 'atob';

const logger = new Logger('TradeTrust');

class TradeTrust {
  public async getRecordDetails(ttFileBuffer) {
    let documentData;
    try {
      const ttObject = JSON.parse(ttFileBuffer.toString('utf-8'));
      documentData = getData(ttObject);
      if (!documentData) {
        throw new Error("Invalid Document")
      }
      const { issuers, network, $template } = documentData;
      const networkChain = ChainInfo[network.chainId];
      if (!networkChain) {
        logger.error('Invalid Network');
        throw new Error('Invalid Network');
      }
      const verificationFragments = await this.verifyByNetwork(networkChain, ttObject);
      const isVerified = isValid(verificationFragments);
      const networkLabel = networkChain.networkLabel;

      const templateUrl = $template.url;
      const currentChainId = network?.chainId;
      const formattedDomainName = issuers[0].identityProof?.location;
      const tokenRegistryAddress = issuers[0].tokenRegistry;
      const providerOrSigner = openAttestation.getProviderDetails(currentChainId);
      let recordDetails = {};
      const nftRegistryData: string = this.getNftRegistryData(tokenRegistryAddress, currentChainId);
      const ownerDetails = await this.getOwnerDetails(tokenRegistryAddress, ttObject, currentChainId);
      const holderDetails = await this.getHolderDetails(tokenRegistryAddress, ttObject, currentChainId);
      const endorsementChainDetail = await this.getEndorsementChainDetails(
        ttObject,
        providerOrSigner,
        providerOrSigner
      );
      recordDetails = {
        isVerified,
        verificationFragments,
        networkLabel,
        domainName: formattedDomainName,
        nftRegistry: nftRegistryData,
        endorsementChain: endorsementChainDetail,
        owner: ownerDetails,
        holder: holderDetails,
        docData: documentData,
        renderUrl: templateUrl,
      };

      if (documentData.attachments) {
        recordDetails['canOpenAttachmentArray'] = this.getCanOpenAttachmentArray(documentData);
      }
      return recordDetails;
    } catch (e) {
      logger.error('erorr jors', e);
      throw e;
    }
  }

  public verifyByNetwork(networkChain, document): Promise<any> {
    const verifyByNetwork = verificationBuilder([...openAttestationVerifiers, openAttestationDidIdentityProof], {
      network: networkChain.networkName
    });
    const verificationFragment = verifyByNetwork(document);
    return verificationFragment;
  }

  public getCanOpenAttachmentArray(documentData) {
    const attachmentArray: any = [];
    documentData.attachments.map(attachment => {
      const { filename, data, type, path } = attachment;
      let filesize = '0';
      let canOpenFile = false;
      const hasBase64 = !!(data && type);
      const downloadHref = hasBase64 ? `data:${type};base64,${data}` : path || '#';
      const decodedData = atob(data);
      canOpenFile = openAttestation.isOpenAttestationFile(decodedData);
      filesize = prettyBytes(decodedData.length);
      attachmentArray.push({
        filename,
        filesize,
        canOpenFile,
        hasBase64,
        downloadHref
      });
    });
    return attachmentArray;
  }

  public getNftRegistryData(tokenRegistryAddress, currentChainId): string {
    const getChainInfo = (chainId: ChainId): ChainInfoObject => {
      const res = ChainInfo[chainId];
      if (!res) throw new UnsupportedNetworkError(chainId);
      return res;
    };

    const makeEtherscanAddressURL = (address: string, chainId: ChainId): string => {
      const baseUrl = getChainInfo(chainId).explorerUrl;
      return new URL(`/address/${address}`, baseUrl).href;
    };

    return currentChainId ? makeEtherscanAddressURL(tokenRegistryAddress, currentChainId) : '#';
  }

  public async getEndorsementChainDetails(document, provider, providerOrSigner) {
    const res = await openAttestation.getHistoryChain(document, provider, providerOrSigner);
    return res;
  }

  public async getOwnerDetails(tokenRegistryAddress, document, chainId) {
    const titleEscrowContract = await openAttestation.getTitleEscrow(tokenRegistryAddress, document, chainId);
    console.log("getOwnerDetails titleEscrowContract",titleEscrowContract);
    const currentBeneficiary = await titleEscrowContract.beneficiary();
    return currentBeneficiary;
  }

  public async getHolderDetails(tokenRegistryAddress, document, chainId) {
    const titleEscrowContract = await openAttestation.getTitleEscrow(tokenRegistryAddress, document, chainId);
    const currentHolder = await titleEscrowContract.holder();
    return currentHolder;
  }

  // public async nominateOwner(tokenRegistry,
  //   tokenId,
  //   newBeneficiary,
  //   network){
      
  //   // maybe need withNetworkAndWalletSignerOption
  //   // token-registry
  //   // token id
  //   // new owner address
  //   const titleEscrow = await openAttestation.getTitleEscrow(tokenRegistryAddress, document, chainId);
  
  //   console.log("Sending transaction to pool");
  //   await openAttestation.validateNominateBeneficiary(newBeneficiary, titleEscrow );
  //   await titleEscrow.callStatic.nominate(newBeneficiary);
  //   const transaction = await titleEscrow.nominate(newBeneficiary);
  //   console.log("transaction.hash",transaction.hash);
  //   console.log("transaction.blockNumber",transaction.blockNumber);
  //   return transaction.wait();

  // }
}

export const tradeTrustService = new TradeTrust();
