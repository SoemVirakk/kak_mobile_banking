package co.istad.mbanking.features.transaction.dto;

import co.istad.mbanking.features.account.dto.AccountSnippetResponse;

import java.math.BigDecimal;
import java.time.LocalDateTime;

public record TransactionResponse(

        AccountSnippetResponse owner,

        AccountSnippetResponse transferReceiver,

        BigDecimal amount,

        String remark,

        String transactionType,

        Boolean status,

        LocalDateTime transactionAt

) {
}
