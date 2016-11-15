package com.nsn.acl.core.impl;

import com.google.common.primitives.Longs;
import com.google.java.contract.Ensures;
import com.google.java.contract.Requires;
import com.nsn.acl.core.*;
import com.nsn.acl.core.jms.AclDomainEntityDeletionMessagePayload;
import com.nsn.acl.core.jms.AclDomainEntityDeletionMessageSender;
import com.nsn.acl.core.jms.AclDomainEntityModificationMessagePayload;
import com.nsn.acl.core.jms.AclDomainEntityModificationMessageSender;
import com.nsn.auth.core.User;
import com.nsn.auth.core.UserNotFoundException;
import com.nsn.auth.core.UserService;
import com.nsn.common.core.AbstractService;
import com.nsn.common.core.Entity;
import com.nsn.common.core.ioc.InitializingBean;
import com.nsn.common.core.RootEntity;
import com.nsn.common.core.cache.EhCacheTemplateFactoryBean;
import com.nsn.common.db.MainTransactional;
import net.sf.ehcache.CacheManager;
import net.sf.ehcache.Ehcache;
import net.sf.ehcache.Element;
import org.springframework.cache.annotation.Cacheable;

import javax.annotation.PostConstruct;
import java.util.*;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

public class AclServiceImpl
    extends AbstractService
    implements AclService,
               InitializingBean
{
  private AclService self;
  private UserService userService;
  private AclSidDao sidDao;
  private AclDomainEntityClassDao domainEntityClassDao;
  private AclDomainEntityDao domainEntityDao;
  private AclDomainEntityModificationMessageSender domainEntityModificationMessageSender;
  private AclDomainEntityDeletionMessageSender domainEntityDeletionMessageSender;
  private AclEntryTemplateDao entryTemplateDao;
  private AclEntryDao entryDao;
  private AclModificationListenerRegister modificationListenerRegister;
  private ThreadLocal<AclModificationContext> modificationContext;
  private EhCacheTemplateFactoryBean hasPermissionCacheTemplateFactoryBean;

  private String hasPermissionCacheNamePrefix;
  private Map<String, Ehcache> hasPermissionCaches = new HashMap<>();

  @Requires("self != null")
  public void setSelf(AclService self)
  {
    this.self = self;
  }

  @Requires("userService != null")
  public void setUserService(UserService userService)
  {
    this.userService = userService;
  }

  @Requires("sidDao != null")
  public void setSidDao(AclSidDao sidDao)
  {
    this.sidDao = sidDao;
  }

  @Requires("domainEntityClassDao != null")
  public void setDomainEntityClassDao(AclDomainEntityClassDao domainEntityClassDao)
  {
    this.domainEntityClassDao = domainEntityClassDao;
  }

  @Requires("domainEntityDao != null")
  public void setDomainEntityDao(AclDomainEntityDao domainEntityDao)
  {
    this.domainEntityDao = domainEntityDao;
  }

  @Requires("domainEntityModificationMessageSender != null")
  public void setDomainEntityModificationMessageSender(AclDomainEntityModificationMessageSender domainEntityModificationMessageSender)
  {
    this.domainEntityModificationMessageSender = domainEntityModificationMessageSender;
  }

  @Requires("domainEntityDeletionMessageSender != null")
  public void setDomainEntityDeletionMessageSender(AclDomainEntityDeletionMessageSender domainEntityDeletionMessageSender)
  {
    this.domainEntityDeletionMessageSender = domainEntityDeletionMessageSender;
  }

  @Requires("entryTemplateDao != null")
  public void setEntryTemplateDao(AclEntryTemplateDao entryTemplateDao)
  {
    this.entryTemplateDao = entryTemplateDao;
  }

  @Requires("entryDao != null")
  public void setEntryDao(AclEntryDao entryDao)
  {
    this.entryDao = entryDao;
  }

  @Requires("modificationListenerRegister != null")
  public void setModificationListenerRegister(AclModificationListenerRegister modificationListenerRegister)
  {
    this.modificationListenerRegister = modificationListenerRegister;
  }

  @Requires("hasPermissionCacheTemplateFactoryBean != null")
  public void setHasPermissionCacheTemplateFactoryBean(EhCacheTemplateFactoryBean hasPermissionCacheTemplateFactoryBean)
  {
    this.hasPermissionCacheTemplateFactoryBean = hasPermissionCacheTemplateFactoryBean;
  }

  @Override
  @PostConstruct
  public void afterPropertiesSet()
  {
    modificationContext = threadLocalFactory.create();
  }

  @Override
  @MainTransactional
  @Cacheable("com.nsn.acl.core.AclPrincipalSidCache")
  public AclSid getPrincipalSid(String userId)
  {
    // lock entire sid list to serialize creation
    if (null == sidDao.getBySidAndPrincipalForUpdate(User.SYSTEM_ADMINISTRATOR, true))
      throw new IllegalStateException(User.SYSTEM_ADMINISTRATOR + " SID not found.");

    AclSid result = sidDao.getBySidAndPrincipal(userId, true);
    if (null == result)
    {
      result = new AclSid();
      result.setSid(userId);
      result.setIsPrincipal(true);
      sidDao.create(result);
      mainDbHelper.flush();
    }

    return result;
  }

  @Override
  @MainTransactional
  @Cacheable("com.nsn.acl.core.AclDomainEntityClassCacheById")
  public AclDomainEntityClass getDomainEntityClass(Long domainEntityClassId)
  {
    AclDomainEntityClass result = domainEntityClassDao.getById(domainEntityClassId);
    if (null == result)
      throw new AclDomainEntityClassNotFoundException(domainEntityClassId);

    return self.getDomainEntityClass(result.getClazz());
  }

  @Override
  public AclDomainEntityClass getDomainEntityClass(Class<? extends Entity> entityClass)
  {
    return self.getDomainEntityClass(entityClass.getName());
  }

  @Override
  @MainTransactional
  @Cacheable("com.nsn.acl.core.AclDomainEntityClassCache")
  public AclDomainEntityClass getDomainEntityClass(String clazz)
  {
    // lock entire list of classes to serialize creation
    if (null == domainEntityClassDao.getByClassForUpdate(RootEntity.class.getName()))
      throw new AclDomainEntityClassNotFoundException(RootEntity.class);

    AclDomainEntityClass result = domainEntityClassDao.getByClass(clazz);
    if (null == result)
    {
      result = new AclDomainEntityClass();
      result.setClazz(clazz);
      domainEntityClassDao.create(result);
      mainDbHelper.flush(); // to get ID
    }

    return result;
  }

  @Override
  public boolean isChildDomainEntityClass(
      Long parentDomainEntityClassId,
      Long childDomainEntityClassId
  )
  {
    return domainEntityClassDao.isChild(parentDomainEntityClassId, childDomainEntityClassId);
  }

  @Override
  @MainTransactional
  public void updateOrCreateDomainEntity(
      Class<? extends Entity> entityClass,
      Long entityId,
      Class<? extends Entity> parentEntityClass,
      Long parentEntityId
  )
  {
    // lock entire tree of business domain entities
    AclDomainEntity rootDomainEntity = domainEntityDao.getByClassAndIdForUpdate(
        self.getDomainEntityClass(RootEntity.class).getClazz(), RootEntity.DEFAULT_ROOT_ENTITY_ID);
    if (null == rootDomainEntity)
      throw new AclDomainEntityNotFoundException(RootEntity.class, RootEntity.DEFAULT_ROOT_ENTITY_ID);

    AclDomainEntity parentDomainEntity;
    if (null != parentEntityClass && null != parentEntityId)
    {
      parentDomainEntity = domainEntityDao.getByClassAndId(self.getDomainEntityClass(parentEntityClass).getClazz(), parentEntityId);
      if (null == parentDomainEntity)
        throw new AclDomainEntityNotFoundException(parentEntityClass, parentEntityId);
    }
    else
      parentDomainEntity = rootDomainEntity;

    // lock this domain entity
    AclDomainEntity domainEntity = domainEntityDao.getByClassAndIdForUpdate(entityClass.getName(), entityId);
    if (null == domainEntity)
    {
      domainEntity = new AclDomainEntity();
      domainEntity.setDomainEntityClass(self.getDomainEntityClass(entityClass));
      domainEntity.setEntityId(entityId);
      domainEntity.setParent(parentDomainEntity);
      domainEntity.setOwnerSid(self.getPrincipalSid(DEFAULT_OWNER));
      domainEntity.setEntriesInheriting(DEFAULT_ENTRIES_INHERITING);
      domainEntityDao.create(domainEntity);

      mainDbHelper.flush();
      try
      {
        for (AclModificationListener modificationListener : modificationListenerRegister.getListeners())
          modificationListener.afterCreateDomainEntity(domainEntity.getId());
      }
      catch (Exception ex)
      {
        throw new IllegalStateException(ex.getMessage(), ex);
      }
    }
    else
    {
      final AclDomainEntity previousParentDomainEntity = domainEntity.getParent();
      domainEntity.setParent(parentDomainEntity);
      domainEntityDao.update(domainEntity);

      mainDbHelper.flush();
      // according to existing logic parentDomainEntity always is not null
      if (null == previousParentDomainEntity || ! parentDomainEntity.getId().equals(previousParentDomainEntity.getId()))
        try
        {
          final Long previousParentDomainEntityId =
              (null == previousParentDomainEntity) ? null : previousParentDomainEntity.getId();
          for (AclModificationListener modificationListener : modificationListenerRegister.getListeners())
            modificationListener.afterDomainEntityParentChange(domainEntity.getId(),
                previousParentDomainEntityId, parentDomainEntity.getId());
        }
        catch (Exception ex)
        {
          throw new IllegalStateException(ex.getMessage(), ex);
        }

      final long domainEntityId = domainEntity.getId();
      mainDbHelper.afterCommit(() -> {
        AclDomainEntityModificationMessagePayload messagePayload = new AclDomainEntityModificationMessagePayload();
        messagePayload.setModifiedDomainEntityIdList(new long[] {domainEntityId});
        domainEntityModificationMessageSender.send(messagePayload);
      });
    }
  }

  @Override
  @MainTransactional
  public void deleteDomainEntity(
      Class<? extends Entity> entityClass,
      Long entityId
  )
  {
    // lock entire tree of business domain entities
    AclDomainEntity rootDomainEntity = domainEntityDao.getByClassAndIdForUpdate(
        self.getDomainEntityClass(RootEntity.class).getClazz(), RootEntity.DEFAULT_ROOT_ENTITY_ID);
    if (null == rootDomainEntity)
      throw new AclDomainEntityNotFoundException(RootEntity.class, RootEntity.DEFAULT_ROOT_ENTITY_ID);

    AclDomainEntity domainEntity = domainEntityDao.getByClassAndIdForUpdate(entityClass.getName(), entityId);
    if (null == domainEntity)
      throw new AclDomainEntityNotFoundException(entityClass, entityId);

    try
    {
      for (AclModificationListener modificationListener : modificationListenerRegister.getListeners())
        modificationListener.beforeDeleteDomainEntity(domainEntity.getId());
    }
    catch (Exception ex)
    {
      throw new IllegalStateException(ex.getMessage(), ex);
    }

    // it expects that external users of ACL (e.g. role system from "auth") removed any usage of this domain entity
    // i.e. there are no ACL entries and/or entry templates which refer to this domain entity

    domainEntityDao.delete(domainEntity.getId());

    mainDbHelper.flush();
    final long domainEntityId = domainEntity.getId();
    mainDbHelper.afterCommit(() -> {
      AclDomainEntityDeletionMessagePayload messagePayload = new AclDomainEntityDeletionMessagePayload();
      messagePayload.setDeletedDomainEntityIdList(new long[] { domainEntityId });
      domainEntityDeletionMessageSender.send(messagePayload);
    });
  }

  @Override
  @Cacheable("com.nsn.acl.core.AclDomainEntityIdCache")
  public Long getDomainEntityId(
      Class<? extends Entity> entityClass,
      Long entityId
  )
  {
    Long result = domainEntityDao.getByClassAndId(entityClass.getName(), entityId).getId();
    if (null == result)
      // it's important to error here not to get 'null' being cached
      throw new AclDomainEntityNotFoundException(entityClass, entityId);

    return result;
  }

  @Override
  @MainTransactional
  public AclDomainEntity getDomainEntity(
      Class<? extends Entity> entityClass,
      Long entityId
  )
  {
    return self.getDomainEntity(self.getDomainEntityId(entityClass, entityId));
  }

  @Override
  @MainTransactional
  public AclDomainEntity getDomainEntity(Long domainEntityId)
  {
    AclDomainEntity result = domainEntityDao.getById(domainEntityId);
    if (null == result)
      throw new AclDomainEntityNotFoundException(domainEntityId);

    return result;
  }

  @Override
  public AclEntryTemplate getEntryTemplate(Long entryTemplateId)
  {
    return entryTemplateDao.getById(entryTemplateId);
  }

  @Override
  public Collection<AclEntryTemplate> getEntryTemplateByDomainEntityAndUser(
      Class<? extends Entity> entityClass,
      Long entityId,
      String userId
  )
  {
    return entryTemplateDao.getByDomainEntityAndPrincipalSid(entityClass, entityId, userId);
  }

  @Override
  public Long createEntryTemplate(AclEntryTemplate entryTemplate)
  {
    checkArgument(entryTemplate.getGranting(), "Deny entries are not supported for now.");

    return entryTemplateDao.create(entryTemplate);
  }

  @Override
  public void deleteEntryTemplate(Long entryTemplateId)
  {
    final boolean shouldFlushModificationContext = !isModificationContextCreated();
    AclModificationContext modificationContext = createModificationContext();
    boolean isFinished = false;
    try
    {
      modificationContext.deleteEntryTemplate(entryTemplateId);
      isFinished = true;
    }
    finally
    {
      if (!isFinished)
        deleteModificationContext();
    }
    if (shouldFlushModificationContext)
      flushModificationContext();
  }

  @Override
  @MainTransactional
  public Collection<AclEntry> getEntryByUser(String userId)
  {
    return entryDao.getBySid(self.getPrincipalSid(userId).getId());
  }

  @Override
  public Collection<AclEntry> getEntryByUserAndTemplate(
      String userId,
      Long entryTemplateId
  )
  {
    return entryDao.getBySidAndTemplate(self.getPrincipalSid(userId).getId(), entryTemplateId);
  }

  @Override
  @MainTransactional
  public void createEntry(
      AclEntryTemplate entryTemplate,
      String userId
  )
      throws
      UserNotFoundException
  {
    // lock user account to serialize permission give/revoke actions
    // it's important to get caches recomputed correctly, see modification listeners which usually do that
    if (null == userService.getUserForUpdate(userId))
      throw new UserNotFoundException(userId);

    AclEntryTemplate resultingEntryTemplate = entryTemplate;
    try
    {
      for (AclModificationListener modificationListener : modificationListenerRegister.getListeners())
      {
        resultingEntryTemplate = modificationListener.beforeCreateEntry(resultingEntryTemplate, userId);
        if (null == resultingEntryTemplate)
          return; // the signal to ignore this entry creation
      }
    }
    catch (Exception ex)
    {
      throw new IllegalStateException(ex.getMessage(), ex);
    }

    checkNotNull(resultingEntryTemplate.getId());
    checkNotNull(resultingEntryTemplate.getDomainEntity());
    checkNotNull(resultingEntryTemplate.getDomainEntity().getId());
    checkNotNull(resultingEntryTemplate.getPermission());
    checkNotNull(resultingEntryTemplate.getPermission().getId());
    checkNotNull(resultingEntryTemplate.getGranting());

    AclEntry entry = new AclEntry();
    entry.setDomainEntity(self.getDomainEntity(resultingEntryTemplate.getDomainEntity().getId()));
    entry.setSid(self.getPrincipalSid(userId));
    entry.setPermission(resultingEntryTemplate.getPermission());
    entry.setGranting(resultingEntryTemplate.getGranting());
    entry.setEntryTemplate(resultingEntryTemplate);

    createEntry(entry);
  }

  @Override
  @MainTransactional
  public void createEntry(
      Class<? extends Entity> entityClass,
      Long entityId,
      AclEntryTemplate entryTemplate,
      String userId
  )
      throws
      UserNotFoundException
  {
    checkNotNull(entryTemplate.getId());
    checkNotNull(entryTemplate.getPermission());
    checkNotNull(entryTemplate.getPermission().getId());
    checkNotNull(entryTemplate.getGranting());

    // lock user account to serialize permission give/revoke actions
    // it's important to get caches recomputed correctly, see modification listeners which usually do that
    if (null == userService.getUserForUpdate(userId))
      throw new UserNotFoundException(userId);

    AclEntry entry = new AclEntry();
    entry.setDomainEntity(self.getDomainEntity(entityClass, entityId));
    entry.setSid(self.getPrincipalSid(userId));
    entry.setPermission(entryTemplate.getPermission());
    entry.setGranting(entryTemplate.getGranting());
    entry.setEntryTemplate(entryTemplate);

    createEntry(entry);
  }

  @Requires("entry != null")
  private void createEntry(AclEntry entry)
  {
    checkNotNull(entry.getDomainEntity());
    checkNotNull(entry.getDomainEntity().getId());
    checkNotNull(entry.getEntryTemplate());
    checkNotNull(entry.getEntryTemplate().getId());
    checkNotNull(entry.getPermission());
    checkNotNull(entry.getPermission().getId());
    checkNotNull(entry.getSid());
    checkNotNull(entry.getSid().getId());
    checkNotNull(entry.getGranting());
    checkArgument(entry.getGranting(), "Deny entries are not supported for now.");

    final boolean shouldFlushModificationContext = !isModificationContextCreated();
    AclModificationContext modificationContext = createModificationContext();
    boolean isFinished = false;
    try
    {
      modificationContext.getModification(entry.getDomainEntity().getId()).createEntry(entry);
      isFinished = true;
    }
    finally
    {
      if (!isFinished)
        deleteModificationContext();
    }
    if (shouldFlushModificationContext)
      flushModificationContext();
  }

  @Override
  @MainTransactional
  public void deleteEntry(
      Long entryTemplateId,
      String userId
  )
      throws
      UserNotFoundException
  {
    // lock user account to serialize permission give/revoke actions
    // it's important to get caches recomputed correctly, see modification listeners which usually do that
    if (null == userService.getUserForUpdate(userId))
      throw new UserNotFoundException(userId);

    try
    {
      for (AclModificationListener modificationListener : modificationListenerRegister.getListeners())
      {
        final boolean shouldContinue = modificationListener.beforeDeleteEntry(entryTemplateId, userId);
        if (!shouldContinue)
          return; // the signal to ignore this entry deletion
      }
    }
    catch (Exception ex)
    {
      throw new IllegalStateException(ex.getMessage(), ex);
    }

    List<AclEntry> entryList = entryDao.getBySidAndTemplate(self.getPrincipalSid(userId).getId(), entryTemplateId);
    if (entryList.isEmpty())
      // someone did it for us, fine...
      return;

    deleteEntry(entryList.get(0));
  }

  @Override
  @MainTransactional
  public void deleteAllEntries(
      Long entryTemplateId,
      String userId
  )
      throws
      UserNotFoundException
  {
    // lock user account to serialize permission give/revoke actions
    // it's important to get caches recomputed correctly, see modification listeners which usually do that
    if (null == userService.getUserForUpdate(userId))
      throw new UserNotFoundException(userId);

    List<AclEntry> entryList = entryDao.getBySidAndTemplate(self.getPrincipalSid(userId).getId(), entryTemplateId);
    if (entryList.isEmpty())
      // someone did it for us, fine...
      return;

    final boolean shouldFlushModificationContext = !isModificationContextCreated();
    createModificationContext();
    boolean isFinished = false;
    try
    {
      entryList.forEach(this::deleteEntry);
      isFinished = true;
    }
    finally
    {
      if (!isFinished)
        deleteModificationContext();
    }
    if (shouldFlushModificationContext)
      flushModificationContext();
  }

  @Override
  @MainTransactional
  public void deleteEntry(
      Class<? extends Entity> entityClass,
      Long entityId,
      Long entryTemplateId,
      String userId
  )
      throws
      UserNotFoundException
  {
    // lock user account to serialize permission give/revoke actions
    // it's important to get caches recomputed correctly, see modification listeners which usually do that
    if (null == userService.getUserForUpdate(userId))
      throw new UserNotFoundException(userId);

    List<AclEntry> entryList = entryDao.getByDomainEntityAndSidAndTemplate(entityClass, entityId,
        self.getPrincipalSid(userId).getId(), entryTemplateId);
    if (entryList.isEmpty())
      // someone did it for us, fine...
      return;

    deleteEntry(entryList.get(0));
  }

  @Requires("entry != null")
  private void deleteEntry(AclEntry entry)
  {
    final boolean shouldFlushModificationContext = !isModificationContextCreated();
    AclModificationContext modificationContext = createModificationContext();
    boolean isFinished = false;
    try
    {
      modificationContext.getModification(entry.getDomainEntity().getId()).deleteEntry(entry);
      isFinished = true;
    }
    finally
    {
      if (!isFinished)
        deleteModificationContext();
    }
    if (shouldFlushModificationContext)
      flushModificationContext();
  }

  @Override
  public boolean isModificationContextCreated()
  {
    return modificationContext.get() != null;
  }

  @Override
  public AclModificationContext createModificationContext()
  {
    AclModificationContext result = modificationContext.get();
    if (null == result)
    {
      result = new AclModificationContext();
      modificationContext.set(result);
    }

    return result;
  }

  @Override
  @MainTransactional
  public void flushModificationContext()
  {
    AclModificationContext context = modificationContext.get();
    if (null == context)
      return;

    try
    {
      mainDbHelper.flush();
      final List<Long> modifiedDomainEntityIdList = new ArrayList<>();
      for (AclModification modification : context.getModifications())
      {
        // lock entire ACL
        AclDomainEntity domainEntity = domainEntityDao.getByIdForUpdate(modification.getDomainEntityId());
        if (null == domainEntity)
          throw new AclDomainEntityNotFoundException(modification.getDomainEntityId());

        for (AclEntry entry : modification.getEntriesToDelete())
          entryDao.delete(entry.getId());

        for (AclEntry entry : modification.getEntriesToCreate())
        {
          entry.setDomainEntity(domainEntity);
          entryDao.create(entry);
        }

        modifiedDomainEntityIdList.add(domainEntity.getId());
      }

      mainDbHelper.flush();
      context.getEntryTemplatesToDelete().forEach(entryTemplateDao::delete);

      mainDbHelper.flush();
      try
      {
        for (AclModificationListener modificationListener : modificationListenerRegister.getListeners())
          modificationListener.afterFlushModificationContext(context);
      }
      catch (Exception ex)
      {
        throw new IllegalStateException(ex.getMessage(), ex);
      }

      if (modifiedDomainEntityIdList.size() > 0)
        mainDbHelper.afterCommit(() -> {
          AclDomainEntityModificationMessagePayload messagePayload = new AclDomainEntityModificationMessagePayload();
          messagePayload.setModifiedDomainEntityIdList(Longs.toArray(modifiedDomainEntityIdList));
          domainEntityModificationMessageSender.send(messagePayload);
        });
    }
    finally
    {
      deleteModificationContext();
    }
  }

  @Override
  public void deleteModificationContext()
  {
    modificationContext.remove();
  }

  @Override
  public boolean hasPermission(
      Class<? extends Entity> entityClass,
      Long entityId,
      PermissionMask permissionMask
  )
  {
    return self.hasPermission(entityClass, entityId, permissionMask, userContext.getUser().getId());
  }

  @Override
  @MainTransactional
  public boolean hasPermission(
      Class<? extends Entity> entityClass,
      Long entityId,
      PermissionMask permissionMask,
      String userId
  )
  {
    AclHasPermissionCacheKey key =
        new AclHasPermissionCacheKey(self.getDomainEntityId(entityClass, entityId), permissionMask.getMask());
    Ehcache cache = self.getHasPermissionCache(userId);
    Element element = cache.get(key);
    if (null == element)
    {
      element = new Element(key, entryDao.hasPermission(entityClass, entityId, permissionMask, userId));
      cache.acquireWriteLockOnKey(key);
      cache.put(element);
      cache.releaseWriteLockOnKey(key);
    }

    return (Boolean) element.getObjectValue();
  }

  @Override
  public void checkPermission(
      Class<? extends Entity> entityClass,
      Long entityId,
      PermissionMask permissionMask
  )
      throws
      NoPermissionException
  {
    self.checkPermission(entityClass, entityId, permissionMask, userContext.getUser().getId());
  }

  @Override
  public void checkPermission(
      Class<? extends Entity> entityClass,
      Long entityId,
      PermissionMask permissionMask,
      String userId
  )
      throws
      NoPermissionException
  {
    if (! self.hasPermission(entityClass, entityId, permissionMask, userId))
      throw new NoPermissionException(entityClass, entityId, permissionMask, userId);
  }

  @Ensures("result != null")
  private String getHasPermissionCacheNamePrefix()
  {
    if (null == hasPermissionCacheNamePrefix)
      synchronized (this)
      {
        if (null == hasPermissionCacheNamePrefix)
          hasPermissionCacheNamePrefix = hasPermissionCacheTemplateFactoryBean.getCacheName();
      }

    return hasPermissionCacheNamePrefix;
  }

  @Override
  public String getHasPermissionCacheName(String userId)
  {
    return getHasPermissionCacheNamePrefix() + "_" + userId;
  }

  @Override
  public Ehcache getHasPermissionCache(String userId)
  {
    Ehcache result = hasPermissionCaches.get(userId);
    if (null == result)
      synchronized (this)
      {
        result = hasPermissionCaches.get(userId);
        if (null == result)
        {
          hasPermissionCacheTemplateFactoryBean.setCacheName(self.getHasPermissionCacheName(userId));
          result = hasPermissionCacheTemplateFactoryBean.create();
          result.removeAll();
          hasPermissionCaches.put(userId, result);
        }
      }

    return result;
  }

  @Override
  public void invalidateHasPermissionCache()
  {
    CacheManager.getInstance().clearAllStartingWith(getHasPermissionCacheNamePrefix());
  }
}
