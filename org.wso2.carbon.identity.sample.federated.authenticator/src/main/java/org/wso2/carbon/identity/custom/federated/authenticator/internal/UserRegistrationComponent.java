package org.wso2.carbon.identity.custom.federated.authenticator.internal;

import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;

import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;

@Component(
        name = "org.wso2.carbon.identity.custom.federated.authenticator.UserRegistrationComponent",
        immediate = true
)
public class UserRegistrationComponent {

    public static RealmService realmService;

    @Reference(
            name = "realm.service",
            service = RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService"
    )
    protected void setRealmService(RealmService realmService) {
        UserRegistrationComponent.realmService = realmService;
        System.out.println("Setting the Realm Service.");
    }

    protected void unsetRealmService(RealmService realmService) {
        UserRegistrationComponent.realmService = null;
        System.out.println("Unset the Realm Service.");
    }


    private AbstractUserStoreManager getUserStoreManager(String username, String tenantDomain) throws org.wso2.carbon.user.core.UserStoreException {
        UserStoreManager userStoreManager = realmService.getBootstrapRealm().getUserStoreManager();
        if (userStoreManager instanceof AbstractUserStoreManager) {
            return (AbstractUserStoreManager) userStoreManager;
        } else {
            throw new org.wso2.carbon.user.core.UserStoreException("UserStoreManager is not an instance of AbstractUserStoreManager");
        }
    }

    public static void registerUser(String username, String password) throws UserStoreException {
        UserStoreManager userStoreManager = realmService.getBootstrapRealm().getUserStoreManager();

        if (!userStoreManager.isExistingUser(username)) {
            userStoreManager.addUser(username, password, null, null, null, true);
            System.out.println("User registered successfully: " + username);
        } else {
            System.out.println("User already exists: " + username);
        }
    }

    public static RealmService getRealmService() {
        return realmService;
    }
}
