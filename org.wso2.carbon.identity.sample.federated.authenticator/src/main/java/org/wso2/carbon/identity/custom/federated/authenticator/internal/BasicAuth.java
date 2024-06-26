package org.wso2.carbon.identity.custom.federated.authenticator.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.custom.federated.authenticator.internal.UserRegistrationComponent;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;

public class BasicAuth {

    private static final Log log = LogFactory.getLog(BasicAuth.class);

    public AbstractUserStoreManager getUserStoreManager(String username, String tenantDomain) throws UserStoreException {
        RealmService realmService = UserRegistrationComponent.getRealmService();
        if (realmService == null) {
            throw new UserStoreException("RealmService is not available");
        }

        UserRealm userRealm = realmService.getTenantUserRealm(IdentityTenantUtil.getTenantId(tenantDomain));
        if (userRealm == null) {
            throw new UserStoreException("UserRealm is not available for tenant: " + tenantDomain);
        }

        return (AbstractUserStoreManager) userRealm.getUserStoreManager();
    }

    public boolean authenticate(String username, String password) {
        String tenantDomain = MultitenantUtils.getTenantDomain(username);
        try {
            AbstractUserStoreManager userStoreManager = getUserStoreManager(username, tenantDomain);
            boolean isAuthenticated = userStoreManager.authenticate(
                    MultitenantUtils.getTenantAwareUsername(username), password);

            if (isAuthenticated) {
                log.info("Authentication successful for user: " + username);
            } else {
                log.info("Authentication failed for user: " + username);
            }

            return isAuthenticated;
        } catch (UserStoreException e) {
            log.error("Error while authenticating user: " + username, e);
            return false;
        }
    }
}
