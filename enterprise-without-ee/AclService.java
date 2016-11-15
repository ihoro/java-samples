package com.nsn.acl.core;

import com.google.java.contract.Ensures;
import com.google.java.contract.Requires;
import com.nsn.auth.core.User;
import com.nsn.auth.core.UserNotFoundException;
import com.nsn.common.core.Entity;
import net.sf.ehcache.Ehcache;

import java.util.Collection;

public interface AclService
{
  String DEFAULT_OWNER = User.SYSTEM_ADMINISTRATOR;
  boolean DEFAULT_ENTRIES_INHERITING = true;

  //--------------------------------------------------------------------------------
  // SID
  //--------------------------------------------------------------------------------

  @Requires("userId != null")
  @Ensures("result != null")
  AclSid getPrincipalSid(String userId);

  //--------------------------------------------------------------------------------
  // Domain entity
  //--------------------------------------------------------------------------------

  @Requires("domainEntityClassId != null")
  @Ensures("result != null")
  AclDomainEntityClass getDomainEntityClass(Long domainEntityClassId)
      throws
      AclDomainEntityClassNotFoundException;

  @Requires("entityClass != null")
  @Ensures("result != null")
  AclDomainEntityClass getDomainEntityClass(Class<? extends Entity> entityClass)
      throws
      AclDomainEntityClassNotFoundException;

  @Requires("clazz != null")
  @Ensures("result != null")
  AclDomainEntityClass getDomainEntityClass(String clazz)
      throws
      AclDomainEntityClassNotFoundException;

  /**
   * Checks whether childDomainEntityClass is direct or indirect child of parentDomainEntityClass.
   */
  @Requires({
      "parentDomainEntityClassId != null",
      "childDomainEntityClassId != null"
  })
  boolean isChildDomainEntityClass(
      Long parentDomainEntityClassId,
      Long childDomainEntityClassId
  );

  @Requires({
      "entityClass != null",
      "! com.nsn.common.core.RootEntity.class.equals(entityClass)",
      "entityId != null",
      "null == parentEntityClass && null == parentEntityId || null != parentEntityClass && null != parentEntityId"
  })
  void updateOrCreateDomainEntity(
      Class<? extends Entity> entityClass,
      Long entityId,
      Class<? extends Entity> parentEntityClass,
      Long parentEntityId
  );

  @Requires({
      "entityClass != null",
      "entityId != null"
  })
  void deleteDomainEntity(
      Class<? extends Entity> entityClass,
      Long entityId
  );

  @Requires({
      "entityClass != null",
      "entityId != null"
  })
  @Ensures("result != null")
  Long getDomainEntityId(
      Class<? extends Entity> entityClass,
      Long entityId
  )
      throws
      AclDomainEntityNotFoundException;

  @Requires({
      "entityClass != null",
      "entityId != null"
  })
  @Ensures("result != null")
  AclDomainEntity getDomainEntity(
      Class<? extends Entity> entityClass,
      Long entityId
  )
      throws
      AclDomainEntityNotFoundException;

  @Requires("domainEntityId != null")
  @Ensures("result != null")
  AclDomainEntity getDomainEntity(Long domainEntityId)
      throws
      AclDomainEntityNotFoundException;

  //--------------------------------------------------------------------------------
  // Entry template
  //--------------------------------------------------------------------------------

  @Requires("entryTemplateId != null")
  AclEntryTemplate getEntryTemplate(Long entryTemplateId);

  @Requires({
      "entityClass != null",
      "entityId != null",
      "userId != null"
  })
  @Ensures("result != null")
  Collection<AclEntryTemplate> getEntryTemplateByDomainEntityAndUser(
      Class<? extends Entity> entityClass,
      Long entityId,
      String userId
  );

  @Requires("entryTemplate != null")
  @Ensures("result != null")
  Long createEntryTemplate(AclEntryTemplate entryTemplate);

  @Requires("entryTemplateId != null")
  void deleteEntryTemplate(Long entryTemplateId);

  //--------------------------------------------------------------------------------
  // Entry
  //--------------------------------------------------------------------------------

  @Requires("userId != null")
  @Ensures("result != null")
  Collection<AclEntry> getEntryByUser(String userId);

  @Requires({
      "userId != null",
      "entryTemplateId != null"
  })
  @Ensures("result != null")
  Collection<AclEntry> getEntryByUserAndTemplate(
      String userId,
      Long entryTemplateId
  );

  @Requires({
      "entryTemplate != null",
      "userId != null"
  })
  void createEntry(
      AclEntryTemplate entryTemplate,
      String userId
  )
      throws
      UserNotFoundException;

  @Requires({
      "entityClass != null",
      "entityId != null",
      "entryTemplate != null",
      "userId != null"
  })
  void createEntry(
      Class<? extends Entity> entityClass,
      Long entityId,
      AclEntryTemplate entryTemplate,
      String userId
  )
      throws
      UserNotFoundException;

  @Requires({
      "entryTemplateId != null",
      "userId != null"
  })
  void deleteEntry(
      Long entryTemplateId,
      String userId
  )
      throws
      UserNotFoundException;

  @Requires({
      "entryTemplateId != null",
      "userId != null"
  })
  void deleteAllEntries(
      Long entryTemplateId,
      String userId
  )
      throws
      UserNotFoundException;

  @Requires({
      "entityClass != null",
      "entityId != null",
      "entryTemplateId != null",
      "userId != null"
  })
  void deleteEntry(
      Class<? extends Entity> entityClass,
      Long entityId,
      Long entryTemplateId,
      String userId
  )
      throws
      UserNotFoundException;

  //--------------------------------------------------------------------------------
  // Modification context
  //--------------------------------------------------------------------------------

  boolean isModificationContextCreated();

  @Ensures("result != null")
  AclModificationContext createModificationContext();

  void flushModificationContext();

  void deleteModificationContext();

  //--------------------------------------------------------------------------------
  // Permission
  //--------------------------------------------------------------------------------

  @Requires({
      "entityClass != null",
      "entityId != null",
      "permissionMask != null"
  })
  boolean hasPermission(
      Class<? extends Entity> entityClass,
      Long entityId,
      PermissionMask permissionMask
  );

  @Requires({
      "entityClass != null",
      "entityId != null",
      "permissionMask != null",
      "userId != null"
  })
  boolean hasPermission(
      Class<? extends Entity> entityClass,
      Long entityId,
      PermissionMask permissionMask,
      String userId
  );

  @Requires({
      "entityClass != null",
      "entityId != null",
      "permissionMask != null"
  })
  void checkPermission(
      Class<? extends Entity> entityClass,
      Long entityId,
      PermissionMask permissionMask
  )
      throws
      NoPermissionException;

  @Requires({
      "entityClass != null",
      "entityId != null",
      "permissionMask != null",
      "userId != null"
  })
  void checkPermission(
      Class<? extends Entity> entityClass,
      Long entityId,
      PermissionMask permissionMask,
      String userId
  )
      throws
      NoPermissionException;

  @Requires("userId != null")
  @Ensures("result != null")
  String getHasPermissionCacheName(String userId);

  @Requires("userId != null")
  @Ensures("result != null")
  Ehcache getHasPermissionCache(String userId);

  void invalidateHasPermissionCache();
}
