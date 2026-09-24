import { executeRepair } from './auth-wizard.mjs';
import { createBlockerHandoffs } from './auth-blocker-handoff.mjs';
const reference = 'env:AUTH_CANONICAL_OWNER_DATABASE_URL';
const fail = code => { throw Object.assign(new Error(code), { code }); };
const matches = (a,b) => a && b && ['revision','sourceDigest','configurationDigest','accountStorage','refreshStorage','serviceId','lookupReference'].every(k=>a[k]===b[k]);
const storageMatches = (a,b) => a.accountStorage===b.accountStorage && a.refreshStorage===b.refreshStorage;
/** Trusted local host adapter, not commands or credentials supplied by an evidence manifest.
 * compareAndSetLookup must atomically update ONLY the dedicated reference and return
 * {snapshot, rollbackHandle}; restoreLookup must CAS against that snapshot.
 */
export async function repairAssertionIssuance({adapter,authorization,expected,host,observe,baseline}={}) {
  let prerequisite;
  let rollbackState='NOT_NEEDED';
  const handler=async()=>{
    if (authorization?.datasourceReference!==reference) {prerequisite='AUTHORIZED_OWNER_DATASOURCE_REQUIRED';fail(prerequisite);}
    if (!expected || expected.revision!==adapter.revision || expected.serviceId!=='auth-local' ||
        !['sourceDigest','configurationDigest','accountStorage','refreshStorage'].every(k=>typeof expected[k]==='string'&&expected[k])) fail('PRECONDITIONS_REQUIRED');
    if(!host || !['observe','inspectProtectedReference','compareAndSetLookup','restoreLookup','reload'].every(k=>typeof host[k]==='function'))fail('SUPPORTED_HOST_ADAPTER_REQUIRED');
    const current=await host.observe();
    if(!matches(expected,current))fail('REPAIR_PRECONDITION_CHANGED');
    // The host resolves its own protected reference; no URL/password crosses this API.
    const approved=await host.inspectProtectedReference(reference);
    if(!approved || approved.reference!==reference || approved.authorized!==true || approved.targetRevision!==expected.revision ||
       approved.targetService!=='auth-local' || approved.provenance!=='TARGET_OWNED_PROTECTED_REFERENCE' || approved.available!==true) {
      prerequisite='AUTHORIZED_OWNER_DATASOURCE_REQUIRED';fail(prerequisite);
    }
    if(current.lookupReference===reference && current.lookupReady===true)return;
    let receipt;
    try {
      receipt=await host.compareAndSetLookup({expected:current,reference});
      if(!receipt?.snapshot || !receipt.rollbackHandle)fail('REPAIR_RECEIPT_REQUIRED');
      rollbackState='PREIMAGE_RETAINED';
      const changed=await host.observe();
      if(!matches(receipt.snapshot,changed) || changed.lookupReference!==reference || !storageMatches(current,changed))fail('STORAGE_SELECTION_CHANGED');
      await host.reload('auth-local');
      const after=await host.observe();
      if(!matches(receipt.snapshot,after) || !storageMatches(current,after) || after.lookupReady!==true)fail('OWNER_LOOKUP_NOT_READY');
    } catch {
      if(receipt?.rollbackHandle) {
        try {
          const restored=await host.restoreLookup({expected:receipt.snapshot,rollbackHandle:receipt.rollbackHandle});
          if(restored!==true){rollbackState='CONCURRENT_CHANGE_PRESERVED';fail('ROLLBACK_CONFLICT');}
          await host.reload('auth-local');
          const recovered=await host.observe();
          if(!matches(current,recovered)||!storageMatches(current,recovered))fail('ROLLBACK_RECOVERY_REQUIRED');
          rollbackState='RESTORED';
        } catch { if(rollbackState!=='CONCURRENT_CHANGE_PRESERVED')rollbackState='RECOVERY_REQUIRED'; }
      }
      fail(rollbackState==='CONCURRENT_CHANGE_PRESERVED'?'ROLLBACK_CONFLICT':rollbackState==='RECOVERY_REQUIRED'?'ROLLBACK_RECOVERY_REQUIRED':'OWNER_LOOKUP_REPAIR_FAILED');
    }
  };
  const report=await executeRepair(adapter,{capabilityId:'assertion.issuance',authorization,handlers:new Map([['assertion.issuance',handler]]),observe,baseline});
  return {...report,repair:{capabilityId:'assertion.issuance',rollbackState},blockerHandoffs:createBlockerHandoffs(report,{
    externalBlockers:prerequisite?{'assertion.issuance':{established:true,reason:prerequisite,owner:'AUTH target configuration operator'}}:{},
  })};
}
