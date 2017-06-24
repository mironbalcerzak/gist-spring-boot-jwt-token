package com.mca.test.spring.application;

import lombok.Getter;
import lombok.Setter;

public final class ApplicationDomains {

    private ApplicationDomains() {
    }

    public static class BaseEntity {
        @Getter
        @Setter
        private Long pk;
    }

    public static class UserAccountEntity extends BaseEntity {
        @Getter
        @Setter
        private String username;

        @Getter
        @Setter
        private String password;
    }


    public static class UserDetailsEntity extends BaseEntity {
        @Getter
        @Setter
        private String username;

        @Getter
        @Setter
        private String name;

        public UserDetailsEntity() {
        }

        public UserDetailsEntity(UserDetailsEntity other) {
            this.setPk(other.getPk());
            this.username = other.username;
            this.name = other.name;
        }
    }


}
