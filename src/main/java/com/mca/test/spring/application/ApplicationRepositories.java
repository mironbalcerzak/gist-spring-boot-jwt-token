package com.mca.test.spring.application;

import com.mca.test.spring.application.ApplicationDomains.BaseEntity;
import com.mca.test.spring.application.ApplicationDomains.UserAccountEntity;
import com.mca.test.spring.application.ApplicationDomains.UserDetailsEntity;

import java.util.HashMap;
import java.util.Map;
import java.util.Random;

public final class ApplicationRepositories {

    private ApplicationRepositories() {
    }

    static private class AbstractInMemoryRepository<T extends BaseEntity> {
        private Random random = new Random();
        private Map<Long, T> cache = new HashMap<>();

        protected Long insert(T o) {
            if (o.getPk() == null) {
                o.setPk(random.nextLong());
            }
            cache.put(o.getPk(), o);
            return o.getPk();
        }

        public T findByPk(Long pk) {
            return cache.get(pk);
        }
    }

    public static class UserAccountInMemoryRepository extends AbstractInMemoryRepository<UserAccountEntity> {
        private Map<String, Long> usernamePkCache = new HashMap<>();

        public UserAccountEntity findByUsername(String username) {
            return findByPk(usernamePkCache.get(username));
        }

        public void addUserAccount(ApplicationDomains.UserAccountEntity entity) {
            Long pk = insert(entity);
            usernamePkCache.put(entity.getUsername(), pk);
        }
    }

    public static class UserDetailsInMemoryRepository extends AbstractInMemoryRepository<UserDetailsEntity> {
        private Map<String, Long> usernamePkCache = new HashMap<>();

        public UserDetailsEntity findByUsername(String username) {
            return findByPk(usernamePkCache.get(username));
        }

        public void addUserAccount(UserDetailsEntity entity) {
            Long pk = insert(entity);
            usernamePkCache.put(entity.getUsername(), pk);
        }
    }

}
