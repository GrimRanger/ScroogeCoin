import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class TxHandler {
  private final UTXOPool _utxoPool;

  /**
   * Creates a public ledger whose current UTXOPool (collection of unspent transaction outputs) is
   * {@code utxoPool}. This should make a copy of utxoPool by using the UTXOPool(UTXOPool uPool)
   * constructor.
   */
  public TxHandler(UTXOPool utxoPool) {
    this._utxoPool = new UTXOPool(utxoPool);
  }

  private boolean isCoinMultipleTimesConsumed(Set <UTXO> claimedUTXO, UTXO utxo) {

    return !claimedUTXO.add(utxo);
  }

  private boolean isValidCoinSignature(Transaction tx, int index, UTXO utxo, Transaction.Input input) {
    Transaction.Output correspondingOutput = _utxoPool.getTxOutput(utxo);

    return Crypto.verifySignature(correspondingOutput.address, tx.getRawDataToSign(index), input.signature);
  }

  private boolean isCoinAvailable(UTXO utxo) {

    return _utxoPool.contains(utxo);
  }

  /**
   * @return true if:
   * (1) all outputs claimed by {@code tx} are in the current UTXO pool,
   * (2) the signatures on each input of {@code tx} are valid,
   * (3) no UTXO is claimed multiple times by {@code tx},
   * (4) all of {@code tx}s output values are non-negative, and
   * (5) the sum of {@code tx}s input values is greater than or equal to the sum of its output
   *     values; and false otherwise.
   */
  public boolean isValidTx(Transaction tx) {
    Set <UTXO> usedUTXO = new HashSet<>();
    double inputSum = 0;
    double outputSum = 0;

    for (int i = 0; i < tx.numInputs(); ++i) {
      Transaction.Input input = tx.getInput(i);
      UTXO utxo = new UTXO(input.prevTxHash, input.outputIndex);

      //check 1: all outputs claimed by tx are in current UTXO pool
      if (!isCoinAvailable(utxo)) {
        return false;
      }

      // check 2: the signatures on each input of tx are valid
      if (!isValidCoinSignature(tx, i, utxo, input)) {
        return false;
      }

      //check 3: no UTXO is claimed multiple times by tx
      if (isCoinMultipleTimesConsumed(usedUTXO, utxo)) {
        return false;
      }

      Transaction.Output output  = _utxoPool.getTxOutput(utxo);
      inputSum += output.value;
    }

    for (Transaction.Output output : tx.getOutputs()) {

      //check 4: all of tx output values are non-negative
      if (output.value < 0) {
        return false;
      }

      outputSum += output.value;
    }

    //check 5: the sum of tx input values is greater than or equal to the sum of its output values
    return inputSum >= outputSum;
  }

  private void addNewCoinsToPool(Transaction tx) {
    List <Transaction.Output> outputs = tx.getOutputs();
    for (int j = 0; j < outputs.size(); ++j) {
      Transaction.Output output = outputs.get(j);
      UTXO utxo = new UTXO(tx.getHash(), j);
      _utxoPool.addUTXO(utxo, output);
    }
  }

  private void removeCoinsFromPool(Transaction tx) {
    for (Transaction.Input input : tx.getInputs()) {
      UTXO utxo = new UTXO(input.prevTxHash, input.outputIndex);
      _utxoPool.removeUTXO(utxo);
    }
  }

  /**
   * Handles each epoch by receiving an unordered array of proposed transactions,
   * checking each transaction for correctness, returning a mutually valid array
   * of accepted transactions, and updating the current UTXO pool as appropriate.
   */
  public Transaction[] handleTxs(Transaction[] possibleTxs) {
    Set<Transaction> validTxs = new HashSet<>();
    for (Transaction tx : possibleTxs) {
      if (isValidTx(tx)) {
        validTxs.add(tx);

        removeCoinsFromPool(tx);
        addNewCoinsToPool(tx);
      }
    }

    Transaction[] validTxArray = new Transaction[validTxs.size()];
    return validTxs.toArray(validTxArray);
  }
}