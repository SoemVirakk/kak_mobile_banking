package co.istad.mbanking.features.transaction;

import co.istad.mbanking.features.transaction.dto.TransactionCreateRequest;
import co.istad.mbanking.features.transaction.dto.TransactionResponse;

public interface TransactionService {

    TransactionResponse transfer(TransactionCreateRequest transactionCreateRequest);

}
