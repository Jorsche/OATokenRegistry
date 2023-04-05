import { UnsupportedNetworkError } from "./error";

export interface ChainInfoObject {
    label: string;
    iconImage: string;
    chainId: ChainId;
    networkName: string; // network name that aligns with existing NETWORK_NAME
    networkLabel: string;
    explorerUrl: string;
    rpcUrl?: string;
    nativeCurrency?: {
      name: string;
      symbol: string;
      decimals: number;
    };
  }
  
  export const AvailableBlockChains = ["ETH", "MATIC"];
  
  type ChainInfo = Record<ChainId, ChainInfoObject>;
  
  export enum ChainId {
    // Localhost
    Local = 1337,
  
    // Ethereum Mainnet
    Ethereum = 1,
  
    // Ethereum Testnet
    Goerli = 5,
    Sepolia = 11155111,
  
    // Polygon
    Polygon = 137,
    PolygonMumbai = 80001,
  }
  
  export const ChainInfo: ChainInfo = {
    [ChainId.Local]: {
      label: "Local",
      chainId: ChainId.Local,
      iconImage: "/static/images/networks/ethereum.gif",
      networkName: "local",
      networkLabel: "Local",
      explorerUrl: "https://localhost/explorer",
    },
    [ChainId.Ethereum]: {
      label: "Ethereum",
      chainId: ChainId.Ethereum,
      iconImage: "/static/images/networks/ethereum.gif",
      networkName: "homestead",
      networkLabel: "Ethereum",
      explorerUrl: "https://etherscan.io",
    },
    [ChainId.Goerli]: {
      label: "Goerli",
      chainId: ChainId.Goerli,
      iconImage: "/static/images/networks/ethereum.gif",
      networkName: "goerli",
      networkLabel: "Goerli",
      explorerUrl: "https://goerli.etherscan.io",
    },
    [ChainId.Sepolia]: {
      label: "Sepolia",
      chainId: ChainId.Sepolia,
      iconImage: "/static/images/networks/ethereum.gif",
      networkName: "sepolia",
      networkLabel: "Sepolia",
      explorerUrl: "https://sepolia.etherscan.io",
      rpcUrl: "https://rpc.sepolia.org",
      nativeCurrency: {
        name: "ETH",
        symbol: "sepETH",
        decimals: 18,
      },
    },
    [ChainId.Polygon]: {
      label: "Polygon (Beta)",
      chainId: ChainId.Polygon,
      iconImage: "/static/images/networks/polygon.gif",
      networkName: "matic",
      networkLabel: "Polygon",
      explorerUrl: "https://polygonscan.com",
      rpcUrl: "https://polygon-rpc.com",
      nativeCurrency: {
        name: "MATIC",
        symbol: "MATIC",
        decimals: 18,
      },
    },
    [ChainId.PolygonMumbai]: {
      label: "Polygon Mumbai",
      chainId: ChainId.PolygonMumbai,
      iconImage: "/static/images/networks/polygon.gif",
      networkName: "maticmum",
      networkLabel: "Polygon Mumbai",
      explorerUrl: "https://mumbai.polygonscan.com",
      rpcUrl: "https://rpc-mumbai.maticvigil.com",
      nativeCurrency: {
        name: "MATIC",
        symbol: "mMATIC",
        decimals: 18,
      },
    },
  };
  



export const getChainInfo = (chainId: ChainId): ChainInfoObject => {
    const res = ChainInfo[chainId];
    if (!res) throw new UnsupportedNetworkError(chainId);
    return res;
  };

export const getChainInfoFromNetworkName = (networkName: string): ChainInfoObject => {
    const res = Object.keys(ChainInfo)
      .map((chainId) => ChainInfo[Number(chainId) as ChainId])
      .find((chainInfo) => chainInfo.networkName === networkName);
    if (!res) throw new UnsupportedNetworkError(networkName);
    return res;
  };
  