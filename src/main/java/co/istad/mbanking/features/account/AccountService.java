package co.istad.mbanking.features.account;

import co.istad.mbanking.features.account.dto.AccountCreateRequest;
import co.istad.mbanking.features.user.dto.UserCreateRequest;

public interface AccountService {

    void createNew(AccountCreateRequest accountCreateRequest);

}
