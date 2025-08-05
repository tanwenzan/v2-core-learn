pragma solidity =0.5.16;

import './interfaces/IUniswapV2Factory.sol';
import './UniswapV2Pair.sol';

contract UniswapV2Factory is IUniswapV2Factory {
    // 交易费地址
    address public feeTo;
    // 允许设置交易费地址的地址，也就是谁有权利去更改 feeTo 的地址，这个在合约创建时需要确定。
    address public feeToSetter;
    // []
    mapping(address => mapping(address => address)) public getPair;
    // 存储所有Pairs
    address[] public allPairs;

    event PairCreated(address indexed token0, address indexed token1, address pair, uint);

    constructor(address _feeToSetter) public {
        feeToSetter = _feeToSetter;
    }

    function allPairsLength() external view returns (uint) {
        return allPairs.length;
    }

    function createPair(address tokenA, address tokenB) external returns (address pair) {
        // 保证两个代币地址相同
        require(tokenA != tokenB, 'UniswapV2: IDENTICAL_ADDRESSES');
        // 对其两个地址进行排序，保证 token0 < token1
        (address token0, address token1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
        // 这里因为 token1 > token0 ,所以只需要判断 token0 不等于0地址即可。
        require(token0 != address(0), 'UniswapV2: ZERO_ADDRESS');
        // 保证两个代币交换匹配关系不存在
        require(getPair[token0][token1] == address(0), 'UniswapV2: PAIR_EXISTS'); // single check is sufficient
        // 获取 池子合约的字节码
        bytes memory bytecode = type(UniswapV2Pair).creationCode;
        // 生成两个代币合约地址组成的salt
        bytes32 salt = keccak256(abi.encodePacked(token0, token1));
        assembly {
            // 创建该合约实例，与用户手动部署合约不同，当salt 相同，返回的合约地址也是相同的。
            // 第一个参数是需要给这个合约地址发送多少ETH。
            // 第二个参数是从内存中哪个地址开始读取合约字节码数据
            // 第三个数据是读取多长
            // 第四个是合约地址生成的盐
            pair := create2(0, add(bytecode, 32), mload(bytecode), salt)
        }
        // 执行初始化池子合约的初始化函数
        IUniswapV2Pair(pair).initialize(token0, token1);
        // 分别添加映射
        getPair[token0][token1] = pair;
        getPair[token1][token0] = pair; // populate mapping in the reverse direction
        // 添加到总的池子合约数组中
        allPairs.push(pair);
        // 发送交易对创建事件
        emit PairCreated(token0, token1, pair, allPairs.length);
    }

    function setFeeTo(address _feeTo) external {
        require(msg.sender == feeToSetter, 'UniswapV2: FORBIDDEN');
        feeTo = _feeTo;
    }

    function setFeeToSetter(address _feeToSetter) external {
        require(msg.sender == feeToSetter, 'UniswapV2: FORBIDDEN');
        feeToSetter = _feeToSetter;
    }
}
