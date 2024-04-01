package co.istad.mbanking.init;

import co.istad.mbanking.domain.AccountType;
import co.istad.mbanking.domain.Role;
import co.istad.mbanking.features.accounttype.AccountTypeRepository;
import co.istad.mbanking.features.user.RoleRepository;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
public class DataInit {

    private final RoleRepository roleRepository;
    private final AccountTypeRepository accountTypeRepository;

    @PostConstruct
    void initRole() {

        // Auto generate role (USER, CUSTOMER, STAFF, ADMIN)
        if (roleRepository.count() < 1) {
            Role user = new Role();
            user.setName("USER");

            Role customer = new Role();
            customer.setName("CUSTOMER");

            Role staff = new Role();
            staff.setName("STAFF");

            Role admin = new Role();
            admin.setName("ADMIN");

            roleRepository.saveAll(
                    List.of(user, customer, staff, admin)
            );
        }

    }

    @PostConstruct
    void initAccountType() {
        if (accountTypeRepository.count() < 1) {
            AccountType savingActType = new AccountType();
            savingActType.setName("Saving Account");
            savingActType.setAlias("saving-account");
            savingActType.setIsDeleted(false);
            savingActType.setDescription("A savings account is a deposit account held at a financial institution that provides security for your principal and a modest interest rate.");
            accountTypeRepository.save(savingActType);

            AccountType payrollActType = new AccountType();
            payrollActType.setName("Payroll Account");
            payrollActType.setAlias("payroll-account");
            payrollActType.setIsDeleted(false);
            payrollActType.setDescription("A payroll account is a type of account used specifically for employee compensation, whether it's to do with salary, wage, or bonuses.");
            accountTypeRepository.save(payrollActType);

            AccountType cardActType = new AccountType();
            cardActType.setName("Card Account");
            cardActType.setAlias("card-account");
            cardActType.setIsDeleted(false);
            cardActType.setDescription("Card Account means the Cardholder's Account(s) with the Bank in respect of which the Card is issued, on which withdrawals/payments shall be debited and lodgements credited when effected by the Cardholder.");
            accountTypeRepository.save(cardActType);
        }
    }

}
