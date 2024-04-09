package co.istad.mbanking.features.transaction;

import co.istad.mbanking.domain.Account;
import co.istad.mbanking.domain.Transaction;
import co.istad.mbanking.features.account.AccountRepository;
import co.istad.mbanking.features.transaction.dto.TransactionCreateRequest;
import co.istad.mbanking.features.transaction.dto.TransactionResponse;
import co.istad.mbanking.mapper.TransactionMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Slf4j
public class TransactionServiceImpl implements TransactionService {

    private final TransactionRepository transactionRepository;
    private final TransactionMapper transactionMapper;
    private final AccountRepository accountRepository;

    @Transactional
    @Override
    public TransactionResponse transfer(TransactionCreateRequest transactionCreateRequest) {

        log.info("transfer(TransactionCreateRequest transactionCreateRequest): {}", transactionCreateRequest);

        // validate owner account no
        Account owner = accountRepository.findByActNo(transactionCreateRequest.ownerActNo())
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND,
                        "Account owner has not been found"
                ));

        // validate transferReceiver account no
        Account transferReceiver = accountRepository.findByActNo(transactionCreateRequest.transferReceiverActNo())
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND,
                        "Account transfer receiver has not been found"
                ));

        // check amount transfer (balance < amount) (act owner only)
        if (owner.getBalance().doubleValue() < transactionCreateRequest.amount().doubleValue()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Insufficient balance");
        }

        // check amount transfer with transfer limit
        if (transactionCreateRequest.amount().doubleValue() >= owner.getTransferLimit().doubleValue()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Transaction has been over the transfer limit");
        }

        // ដកលុយចេញពីគណនី
        owner.setBalance(owner.getBalance().subtract(transactionCreateRequest.amount()));

        // បញ្ចូលលុយទៅគណនី
        transferReceiver.setBalance(transferReceiver.getBalance().add(transactionCreateRequest.amount()));

        Transaction transaction = transactionMapper.fromTransactionCreateRequest(transactionCreateRequest);
        transaction.setOwner(owner);
        transaction.setTransferReceiver(transferReceiver);
        transaction.setTransactionType("TRANSFER");
        transaction.setTransactionAt(LocalDateTime.now());
        transaction.setStatus(true);
        transaction = transactionRepository.save(transaction);

        return transactionMapper.toTransactionResponse(transaction);
    }

}
