package co.istad.mbanking.features.account;

import co.istad.mbanking.domain.Account;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AccountRepository
        extends JpaRepository<Account, Long> {
}
