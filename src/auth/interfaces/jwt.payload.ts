export interface JwtPayload{
    id: string;
    iat?: number; //fecha de creaciòn ---> opcional
    exp?: number; //fecha de expiracxion ---> opcional

}