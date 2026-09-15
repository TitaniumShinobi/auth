import type {RefreshTokenStore} from './refreshTokenStore.js';
import type {EnrollmentStore} from './enrollmentStore.js';
/** Operator-only operation; retains account identity and legal acceptance rows. */
export async function retireProductAdmission(input:{userId:string;lifeSubject:string;retiredOwnerId:string;authorized:boolean},deps:{
 storage:{findUserById(id:string):Promise<any>};refresh:RefreshTokenStore;enrollment:EnrollmentStore;
}) {
 if(input.authorized!==true || !input.userId || !input.lifeSubject || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(input.retiredOwnerId))throw new Error('RETIREMENT_SCOPE_REQUIRED');
 const user=await deps.storage.findUserById(input.userId);
 if(!user || user.lifeUserId!==input.lifeSubject)throw new Error('RETIREMENT_IDENTITY_MISMATCH');
 if(!deps.refresh.revokeUserSessions)throw new Error('SESSION_RETIREMENT_UNSUPPORTED');
 // Revoke first: a concurrent old completion can never become usable even
 // if it writes after the retained admission rows are marked expired.
 const revokedSessions=await deps.refresh.revokeUserSessions(user.id,'chatty','product_owner_retired');
 await deps.enrollment.retireOwnerAdmission(input.lifeSubject,input.retiredOwnerId);
 return {ok:true,revokedSessions,identityRetained:true,legalReceiptsRetained:true};
}
