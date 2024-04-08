package co.istad.mbanking.features.account;

import co.istad.mbanking.features.account.dto.AccountCreateRequest;
import co.istad.mbanking.features.account.dto.AccountRenameRequest;
import co.istad.mbanking.features.account.dto.AccountResponse;
import org.springframework.data.domain.Page;

import java.util.List;

public interface AccountService {

    Page<AccountResponse> findList(int page, int size);

    void hideAccount(String actNo);

    AccountResponse renameByActNo(String actNo,
                                  AccountRenameRequest accountRenameRequest);

    void createNew(AccountCreateRequest accountCreateRequest);

    AccountResponse findByActNo(String actNo);

}
