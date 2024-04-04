package co.istad.mbanking.mapper;

import co.istad.mbanking.domain.Account;
import co.istad.mbanking.features.account.dto.AccountCreateRequest;
import co.istad.mbanking.features.account.dto.AccountResponse;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface AccountMapper {

    Account fromAccountCreateRequest(AccountCreateRequest accountCreateRequest);

    AccountResponse toAccountResponse(Account account);

}
