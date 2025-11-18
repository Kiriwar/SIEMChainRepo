const Web3 = require('web3').default;

// 1. Connect to Ganache's RPC endpoint
const w3 = new Web3('http://127.0.0.1:7545'); 

// 2. Define your contract address and ABI
const contractAddress = '0x0Cd2218A869Ff19eBdf926cCa979801c0e6FA16f'; // Replace with your deployed contract address
const contractABI = [
	{
		"inputs": [],
		"stateMutability": "nonpayable",
		"type": "constructor"
	},
	{
		"anonymous": false,
		"inputs": [
			{
				"indexed": true,
				"internalType": "uint256",
				"name": "epochId",
				"type": "uint256"
			},
			{
				"indexed": false,
				"internalType": "string",
				"name": "rootHash",
				"type": "string"
			},
			{
				"indexed": false,
				"internalType": "string",
				"name": "batchHash",
				"type": "string"
			},
			{
				"indexed": false,
				"internalType": "uint256",
				"name": "timestamp",
				"type": "uint256"
			},
			{
				"indexed": false,
				"internalType": "address",
				"name": "submitter",
				"type": "address"
			}
		],
		"name": "EpochFinalized",
		"type": "event"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "epochId",
				"type": "uint256"
			},
			{
				"internalType": "string",
				"name": "root",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "batch",
				"type": "string"
			}
		],
		"name": "finalizeEpoch",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "owner",
		"outputs": [
			{
				"internalType": "address",
				"name": "",
				"type": "address"
			}
		],
		"stateMutability": "view",
		"type": "function"
	}
];

const contractInstance = new w3.eth.Contract(contractABI, contractAddress);

async function getEventByBlockNumber(targetBlockNumber) {
    try {
        console.log(`Querying events in block ${targetBlockNumber}...`);

        // Use the event name and specify the block range
        const events = await contractInstance.getPastEvents('EpochFinalized', {
            // Set both fromBlock and toBlock to the specific number
            fromBlock: targetBlockNumber,
            toBlock: targetBlockNumber 
        });

        if (events.length === 0) {
            console.log(`\nNo 'EpochFinalized' events found in block ${targetBlockNumber}.`);
            return;
        }

        console.log(`\n✅ Found ${events.length} event(s) in Block ${targetBlockNumber}:`);
        
        events.forEach((event) => {
            console.log('--------------------------------------------------');
            console.log(`Block Number: ${event.blockNumber}`);
            console.log(`Transaction Hash: ${event.transactionHash}`);
            //console.log(`Logged Value: ${event.returnValues.value}`); // Access the 'value' argument
            console.log(`Logged by Sender: ${event.returnValues.sender}`);
			console.log(event);
        });

    } catch (error) {
        console.error('Error querying events:', error);
    }
}

// Example usage: Query events specifically in block number 5
getEventByBlockNumber(32);